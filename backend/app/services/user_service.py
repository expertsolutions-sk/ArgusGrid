"""User management (ARG-005, ARG-006, ARG-011). Visibility, level and last-administrator rules live here."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.context import RequestContext
from app.core.errors import ApiError, forbidden, invalid, not_found
from app.core.permissions import ADMINISTRATOR, DEVICE_AGENT, Cap
from app.models.identity import Role, SessionRecord, User
from app.services.audit_service import AuditService, diff
from app.services.credential_service import CredentialService
from app.services.lockout_service import LockoutService
from app.services.mail_service import MailService
from app.services.notifications import SecurityNotifier
from app.services.role_service import RoleService

USERNAME = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
OWNER_LEVEL = 10**6
EDITABLE = ("email", "full_name", "role", "locale", "is_active")
LOCALES = ("en", "sk")
MAX_PAGE_SIZE = 100


@dataclass(frozen=True)
class Viewer:
    """Who is acting, reduced to what the user rules need."""

    ctx: RequestContext
    capabilities: frozenset[str]
    level: int
    role_name: str
    user_id: int | None
    is_owner: bool = False

    def has(self, capability: str) -> bool:
        return self.is_owner or capability in self.capabilities

    @property
    def can_view_admins(self) -> bool:
        return self.has(Cap.USER_VIEW_ADMINS)


class UserService:
    def __init__(self, session: Session, clock: Clock, roles: RoleService, credentials: CredentialService,
                 lockout: LockoutService, audit: AuditService, mail: MailService,
                 notifier: SecurityNotifier) -> None:
        self._s = session
        self._clock = clock
        self._roles = roles
        self._credentials = credentials
        self._lockout = lockout
        self._audit = audit
        self._mail = mail
        self._notifier = notifier

    # -- visibility ---------------------------------------------------------------------------------
    def _base(self, viewer: Viewer):  # type: ignore[no-untyped-def]
        stmt = select(User).join(Role, User.role_id == Role.id)
        if not viewer.can_view_admins:  # IDN-031: removed from every query for lower roles
            stmt = stmt.where(Role.name != ADMINISTRATOR)
        return stmt

    def _load(self, viewer: Viewer, user_id: int) -> User:
        user = self._s.execute(self._base(viewer).where(User.id == user_id)).scalar_one_or_none()
        if user is None:
            raise not_found("user.not_found")  # "not found", never "forbidden" (IDN-031)
        return user

    def _require(self, viewer: Viewer, capability: str) -> None:
        if not viewer.has(capability):
            raise forbidden()

    def _require_level(self, viewer: Viewer, target: User) -> None:
        if not viewer.is_owner and target.role.security_level > viewer.level:
            raise not_found("user.not_found")

    # -- representation -----------------------------------------------------------------------------
    def dto(self, user: User) -> dict[str, Any]:
        return {
            "id": user.id, "username": user.username, "email": user.email, "full_name": user.full_name,
            "role": user.role.name, "locale": user.locale, "is_active": user.is_active,
            "is_service": user.is_service, "must_change_password": user.must_change_password,
            "lock": self._lockout.describe_lock(user),
            "password_expires_at": user.password_expires_at.isoformat() if user.password_expires_at else None,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "created_at": user.created_at.isoformat(),
        }

    @staticmethod
    def _snapshot(user: User) -> dict[str, Any]:
        return {"email": user.email, "full_name": user.full_name, "role": user.role.name, "locale": user.locale,
                "is_active": user.is_active}

    # -- read ---------------------------------------------------------------------------------------
    def list(self, viewer: Viewer, *, search: str = "", role: str = "", page: int = 1,
             page_size: int = 20) -> dict[str, Any]:
        self._require(viewer, Cap.USER_VIEW)
        page = max(1, page)
        page_size = min(max(1, page_size), MAX_PAGE_SIZE)
        stmt = self._base(viewer)
        if search.strip():
            like = f"%{search.strip().lower()}%"
            stmt = stmt.where(or_(func.lower(User.username).like(like), func.lower(User.email).like(like),
                                  func.lower(User.full_name).like(like)))
        if role:
            stmt = stmt.where(Role.name == role)
        total = self._s.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()  # IDN-033
        rows = self._s.execute(
            stmt.order_by(User.username_key).offset((page - 1) * page_size).limit(page_size)
        ).scalars().all()
        return {"items": [self.dto(u) for u in rows], "total": total, "page": page, "page_size": page_size}

    def get(self, viewer: Viewer, user_id: int) -> dict[str, Any]:
        self._require(viewer, Cap.USER_VIEW)
        return self.dto(self._load(viewer, user_id))

    def assignable_roles(self, viewer: Viewer) -> list[dict[str, Any]]:
        roles = self._s.execute(select(Role).order_by(Role.security_level.desc())).scalars()
        out = []
        for r in roles:
            if r.name == DEVICE_AGENT:  # service accounts are made through the device credential flow
                continue
            if r.name == ADMINISTRATOR and not viewer.can_view_admins:
                continue
            if not viewer.is_owner and r.security_level > viewer.level:
                continue
            out.append({"id": r.id, "name": r.name, "security_level": r.security_level})
        return out

    # -- create -------------------------------------------------------------------------------------
    def create(self, viewer: Viewer, *, username: str, email: str, full_name: str, role: str, locale: str,
               password: str, send_email: bool) -> dict[str, Any]:
        self._require(viewer, Cap.USER_CREATE)
        problems: list[dict[str, Any]] = []
        username = username.strip()
        email = email.strip()
        if not USERNAME.match(username):
            problems.append({"code": "user.username_invalid", "fields": ["username"]})
        if not EMAIL.match(email) or len(email) > 254:
            problems.append({"code": "user.email_invalid", "fields": ["email"]})
        if locale not in LOCALES:
            problems.append({"code": "user.locale_invalid", "fields": ["locale"]})
        if len(full_name) > 128:
            problems.append({"code": "user.full_name_too_long", "fields": ["full_name"]})
        if problems:
            raise invalid("user.invalid", problems)

        role_row = self._roles.by_name(role)
        if (role_row is None or role_row.name == DEVICE_AGENT
                or (role_row.name == ADMINISTRATOR and not viewer.can_view_admins)
                or (not viewer.is_owner and role_row.security_level > viewer.level)):
            raise invalid("user.invalid", [{"code": "user.role_invalid", "fields": ["role"]}])
        if self._s.execute(select(User.id).where(User.username_key == username.lower())).first() is not None:
            raise ApiError(409, "user.username_taken")

        user = User(username=username, username_key=username.lower(), email=email, full_name=full_name.strip(),
                    role_id=role_row.id, password_hash="", locale=locale, is_active=True,
                    created_at=self._clock.now(), created_by=viewer.ctx.actor.name or "system")
        self._credentials.apply_to_new_user(user, password, must_change=True)  # policy enforced, may raise 422
        self._s.add(user)
        self._s.flush()
        self._audit.record("user.create", viewer.ctx, object_type="user", object_id=user.id,
                           changes=diff({}, {"username": username, **self._snapshot(user)}))
        queued = None
        if send_email:
            queued = self._mail.queue("user.created", user, {"temp_password": password, "role_name": role_row.name})
        result = self.dto(user)
        result["email_queued"] = queued is not None
        result["email_configured"] = self._mail.configured()
        return result

    # -- update -------------------------------------------------------------------------------------
    def update(self, viewer: Viewer, user_id: int, fields: dict[str, Any]) -> dict[str, Any]:
        self._require(viewer, Cap.USER_EDIT)
        user = self._load(viewer, user_id)
        self._require_level(viewer, user)
        unknown = set(fields) - set(EDITABLE)
        if unknown:
            raise invalid("user.invalid", [{"code": "user.field_unknown", "fields": sorted(unknown)}])  # no mass assignment
        before = self._snapshot(user)
        is_self = viewer.user_id is not None and viewer.user_id == user.id
        problems: list[dict[str, Any]] = []

        if "email" in fields:
            email = str(fields["email"]).strip()
            if not EMAIL.match(email) or len(email) > 254:
                problems.append({"code": "user.email_invalid", "fields": ["email"]})
            else:
                user.email = email
        if "full_name" in fields:
            name = str(fields["full_name"]).strip()
            if len(name) > 128:
                problems.append({"code": "user.full_name_too_long", "fields": ["full_name"]})
            else:
                user.full_name = name
        if "locale" in fields:
            if fields["locale"] not in LOCALES:
                problems.append({"code": "user.locale_invalid", "fields": ["locale"]})
            else:
                user.locale = fields["locale"]
        if problems:
            raise invalid("user.invalid", problems)

        revoke = False
        if "role" in fields and fields["role"] != user.role.name:
            self._require(viewer, Cap.USER_ROLE_ASSIGN)
            if is_self:
                raise forbidden("user.cannot_change_own_role")
            new_role = self._roles.by_name(str(fields["role"]))
            if (new_role is None or new_role.name == DEVICE_AGENT
                    or (new_role.name == ADMINISTRATOR and not viewer.can_view_admins)
                    or (not viewer.is_owner and new_role.security_level > viewer.level)):
                raise invalid("user.invalid", [{"code": "user.role_invalid", "fields": ["role"]}])
            if user.role.name == ADMINISTRATOR and self._is_last_admin(user):
                raise ApiError(409, "user.last_administrator")
            user.role_id = new_role.id
            user.role = new_role
            revoke = True
        if "is_active" in fields and bool(fields["is_active"]) != user.is_active:
            if is_self:
                raise forbidden("user.cannot_deactivate_self")
            if not bool(fields["is_active"]) and user.role.name == ADMINISTRATOR and self._is_last_admin(user):
                raise ApiError(409, "user.last_administrator")
            user.is_active = bool(fields["is_active"])
            revoke = revoke or not user.is_active
        if revoke:
            self._revoke(user)  # IDN-003: role reduction and deactivation end the sessions
        after = self._snapshot(user)
        self._audit.record("user.update", viewer.ctx, object_type="user", object_id=user.id,
                           changes=diff(before, after))
        return self.dto(user)

    # -- delete -------------------------------------------------------------------------------------
    def delete(self, viewer: Viewer, user_id: int) -> None:
        self._require(viewer, Cap.USER_DELETE)
        user = self._load(viewer, user_id)
        self._require_level(viewer, user)
        if viewer.user_id is not None and viewer.user_id == user.id:
            raise forbidden("user.cannot_delete_self")
        if user.role.name == ADMINISTRATOR and self._is_last_admin(user):
            raise ApiError(409, "user.last_administrator")
        snapshot = {"username": user.username, **self._snapshot(user)}
        self._audit.record("user.delete", viewer.ctx, object_type="user", object_id=user.id,
                           changes=diff(snapshot, {}))
        self._s.delete(user)
        self._s.flush()

    # -- lock, unlock, reset ------------------------------------------------------------------------
    def lock(self, viewer: Viewer, user_id: int, reason: str) -> dict[str, Any]:
        self._require(viewer, Cap.USER_LOCK)
        user = self._load(viewer, user_id)
        self._require_level(viewer, user)
        if viewer.user_id is not None and viewer.user_id == user.id:
            raise forbidden("user.cannot_lock_self")  # LCK-017
        if user.role.name == ADMINISTRATOR and self._is_last_admin(user):
            raise ApiError(409, "user.last_administrator")
        self._lockout.lock_manually(user, viewer.ctx, reason)
        self._notifier.account_locked(user, permanent=True, until=None, manual=True)
        return self.dto(user)

    def unlock(self, viewer: Viewer, user_id: int) -> dict[str, Any]:
        self._require(viewer, Cap.USER_UNLOCK)
        user = self._load(viewer, user_id)
        self._require_level(viewer, user)
        try:
            outcome = self._lockout.unlock(user, viewer.ctx)
        except PermissionError as exc:
            raise forbidden("user.unlock_not_allowed") from exc
        queued = self._mail.queue("user.unlocked", user, {"temp_password": outcome.temporary_password or ""})
        result = self.dto(user)
        result["after_unlock"] = outcome.after_unlock
        result["email_queued"] = queued is not None
        result["email_configured"] = self._mail.configured()
        if outcome.temporary_password and queued is None:
            result["temporary_password"] = outcome.temporary_password  # no address: the admin hands it over once
        return result

    def reset_password(self, viewer: Viewer, user_id: int, password: str) -> dict[str, Any]:
        self._require(viewer, Cap.USER_RESET_PASSWORD)
        user = self._load(viewer, user_id)
        self._require_level(viewer, user)
        if viewer.user_id is not None and viewer.user_id == user.id:
            raise forbidden("user.cannot_reset_self")
        self._credentials.set_password(user, password, admin_set=True, must_change_next=True)
        self._revoke(user)
        self._audit.record("user.reset_password", viewer.ctx, object_type="user", object_id=user.id)
        queued = self._mail.queue("user.password_reset", user, {"temp_password": password})
        result = self.dto(user)
        result["email_queued"] = queued is not None
        result["email_configured"] = self._mail.configured()
        return result

    # -- helpers ------------------------------------------------------------------------------------
    def _is_last_admin(self, user: User) -> bool:
        others = self._s.execute(
            select(func.count()).select_from(User).join(Role, User.role_id == Role.id).where(
                Role.name == ADMINISTRATOR, User.is_active.is_(True), User.id != user.id)
        ).scalar_one()
        return others == 0

    def _revoke(self, user: User) -> None:
        self._s.execute(
            update(SessionRecord).where(SessionRecord.user_id == user.id, SessionRecord.revoked_at.is_(None))
            .values(revoked_at=self._clock.now())
        )
