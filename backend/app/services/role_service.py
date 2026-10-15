"""Roles and capabilities stored in the database (IDN-004). Seeding and lookups."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.permissions import ADMINISTRATOR, ALL_CAPABILITIES, DEFAULT_ROLES, DEVICE_ONLY
from app.models.identity import Role, RolePermission


class RoleService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def seed_defaults(self) -> None:
        """Create missing default roles. Existing roles keep their runtime edits, except that the
        Administrator role always receives every non-device capability (rules/03)."""
        existing = {r.name: r for r in self._session.execute(select(Role)).scalars()}
        for default in DEFAULT_ROLES:
            role = existing.get(default.name)
            if role is None:
                role = Role(name=default.name, description=default.description,
                            security_level=default.level, is_system=True)
                role.permissions = [RolePermission(permission=c) for c in sorted(default.caps)]
                self._session.add(role)
        self._session.flush()
        admin = self.by_name(ADMINISTRATOR)
        if admin is not None:
            have = admin.capabilities
            for cap in ALL_CAPABILITIES:
                if cap not in DEVICE_ONLY and cap not in have:
                    admin.permissions.append(RolePermission(permission=cap))
        self._session.flush()

    def by_name(self, name: str) -> Role | None:
        return self._session.execute(select(Role).where(Role.name == name)).scalar_one_or_none()

    def levels(self) -> dict[str, int]:
        return {r.name: r.security_level for r in self._session.execute(select(Role)).scalars()}
