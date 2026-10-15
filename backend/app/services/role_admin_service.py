"""Role and capability administration (IDN-004, ARG-010): editable at runtime, escalation-safe."""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.errors import ApiError, forbidden, invalid, not_found
from app.core.permissions import ADMINISTRATOR, ALL_CAPABILITIES, DEVICE_AGENT, DEVICE_ONLY, Cap
from app.models.identity import Role, RolePermission, SessionRecord, User
from app.services.audit_service import AuditService, diff
from app.services.user_service import Viewer

ROLE_NAME = re.compile(r"^[A-Za-z0-9 ._-]{3,64}$")


class RoleAdminService:
    def __init__(self, session: Session, clock: Clock, audit: AuditService) -> None:
        self._s = session
        self._clock = clock
        self._audit = audit

    def _dto(self, role: Role, user_count: int) -> dict[str, Any]:
        return {
            "id": role.id, "name": role.name, "description": role.description, "security_level": role.security_level,
            "is_system": role.is_system, "capabilities": sorted(role.capabilities), "user_count": user_count,
            "locked": role.name == ADMINISTRATOR,
        }

    def catalogue(self) -> list[str]:
        return sorted(ALL_CAPABILITIES)

    def list(self, viewer: Viewer) -> list[dict[str, Any]]:
        if not (viewer.has(Cap.ROLE_VIEW) or viewer.has(Cap.ROLE_MANAGE)):
            raise forbidden()
        roles = self._s.execute(select(Role).order_by(Role.security_level.desc(), Role.name)).scalars().all()
        counts = dict(self._s.execute(select(User.role_id, func.count()).group_by(User.role_id)).all())
        out = []
        for r in roles:
            if r.name == ADMINISTRATOR and not viewer.can_view_admins:
                continue  # the administrator role is not shown to lower roles (IDN-031)
            out.append(self._dto(r, counts.get(r.id, 0)))
        return out

    def _get(self, viewer: Viewer, role_id: int) -> Role:
        role = self._s.get(Role, role_id)
        if role is None or (role.name == ADMINISTRATOR and not viewer.can_view_admins):
            raise not_found("role.not_found")
        return role

    def _check_capabilities(self, viewer: Viewer, role_name: str, caps: list[str], current: set[str]) -> set[str]:
        wanted = set(caps)
        unknown = wanted - set(ALL_CAPABILITIES)
        if unknown:
            raise invalid("role.invalid", [{"code": "role.capability_unknown", "fields": sorted(unknown)}])
        if (wanted & DEVICE_ONLY) and role_name != DEVICE_AGENT:
            raise invalid("role.invalid", [{"code": "role.device_capability", "fields": sorted(wanted & DEVICE_ONLY)}])
        added = wanted - current
        if not viewer.is_owner and not added <= set(viewer.capabilities):
            # a role manager cannot hand out capabilities they do not hold themselves
            raise invalid("role.invalid", [{"code": "role.escalation", "fields": sorted(added - set(viewer.capabilities))}])
        return wanted

    def update(self, viewer: Viewer, role_id: int, description: str | None, capabilities: list[str] | None) -> dict[str, Any]:
        if not viewer.has(Cap.ROLE_MANAGE):
            raise forbidden()
        role = self._get(viewer, role_id)
        if role.name == ADMINISTRATOR:
            raise ApiError(409, "role.administrator_fixed")  # always holds every non-device capability
        if not viewer.is_owner and role.security_level >= viewer.level:
            raise forbidden("role.level_too_high")
        before = {"description": role.description, "capabilities": sorted(role.capabilities)}
        removed: set[str] = set()
        if description is not None:
            role.description = description.strip()[:255]
        if capabilities is not None:
            current = role.capabilities
            wanted = self._check_capabilities(viewer, role.name, capabilities, current)
            removed = current - wanted
            # apply the difference only: replacing the whole collection inserts before it deletes
            for row in [p for p in role.permissions if p.permission in removed]:
                role.permissions.remove(row)
            for cap in sorted(wanted - current):
                role.permissions.append(RolePermission(permission=cap))
        self._s.flush()
        if removed:  # IDN-003: a reduced role ends the sessions of its users
            self._s.execute(
                update(SessionRecord)
                .where(SessionRecord.revoked_at.is_(None),
                       SessionRecord.user_id.in_(select(User.id).where(User.role_id == role.id)))
                .values(revoked_at=self._clock.now())
            )
        after = {"description": role.description, "capabilities": sorted(role.capabilities)}
        self._audit.record("role.update", viewer.ctx, object_type="role", object_id=role.id,
                           changes=diff(before, after), details={"name": role.name})
        return self._dto(role, self._count(role.id))

    def create(self, viewer: Viewer, name: str, description: str, security_level: int,
               capabilities: list[str]) -> dict[str, Any]:
        if not viewer.has(Cap.ROLE_MANAGE):
            raise forbidden()
        name = name.strip()
        if not ROLE_NAME.match(name):
            raise invalid("role.invalid", [{"code": "role.name_invalid", "fields": ["name"]}])
        if not viewer.is_owner and not 0 <= security_level < viewer.level:
            raise invalid("role.invalid", [{"code": "role.level_invalid", "fields": ["security_level"]}])
        if self._s.execute(select(Role.id).where(func.lower(Role.name) == name.lower())).first() is not None:
            raise ApiError(409, "role.name_taken")
        wanted = self._check_capabilities(viewer, name, capabilities, set())
        role = Role(name=name, description=description.strip()[:255], security_level=security_level, is_system=False)
        role.permissions = [RolePermission(permission=c) for c in sorted(wanted)]
        self._s.add(role)
        self._s.flush()
        self._audit.record("role.create", viewer.ctx, object_type="role", object_id=role.id,
                           changes=diff({}, {"name": name, "security_level": security_level,
                                             "capabilities": sorted(wanted)}))
        return self._dto(role, 0)

    def delete(self, viewer: Viewer, role_id: int) -> None:
        if not viewer.has(Cap.ROLE_MANAGE):
            raise forbidden()
        role = self._get(viewer, role_id)
        if role.is_system:
            raise ApiError(409, "role.system_role")
        if self._count(role.id) > 0:
            raise ApiError(409, "role.in_use")
        self._audit.record("role.delete", viewer.ctx, object_type="role", object_id=role.id,
                           details={"name": role.name})
        self._s.delete(role)
        self._s.flush()

    def _count(self, role_id: int) -> int:
        return self._s.execute(select(func.count()).select_from(User).where(User.role_id == role_id)).scalar_one()
