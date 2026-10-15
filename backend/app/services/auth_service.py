"""Login, logout and password change (rules/19, rules/18)."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.context import Actor, RequestContext
from app.core.errors import ApiError, forbidden, invalid
from app.core.security import verify_password
from app.models.identity import SessionRecord, User
from app.services.accounts_file import AccountsFile
from app.services.audit_service import AuditService
from app.services.credential_service import CredentialService
from app.services.lockout_service import LockoutService
from app.services.notifications import SecurityNotifier
from app.services.owner_service import OwnerService
from app.services.session_service import SessionService

MAX_USERNAME_LENGTH = 64


@dataclass
class LoginResult:
    token: str
    session: SessionRecord
    user: User | None  # None for the owner path


def invalid_credentials() -> ApiError:
    """LCK-011: one response for unknown user, wrong password, locked and inactive accounts."""
    return ApiError(401, "invalid_credentials")


class AuthService:
    def __init__(
        self,
        db: Session,
        clock: Clock,
        sessions: SessionService,
        lockout: LockoutService,
        audit: AuditService,
        owner: OwnerService,
        credentials: CredentialService,
        accounts: AccountsFile,
        notifier: SecurityNotifier,
    ) -> None:
        self._db = db
        self._clock = clock
        self._sessions = sessions
        self._lockout = lockout
        self._audit = audit
        self._owner = owner
        self._credentials = credentials
        self._accounts = accounts
        self._notifier = notifier

    def login(self, username: str, password: str, ctx: RequestContext) -> LoginResult:
        username = (username or "").strip()[:MAX_USERNAME_LENGTH]
        user = self._db.execute(
            select(User).where(User.username_key == username.lower())
        ).scalar_one_or_none()

        if user is None:
            return self._login_unknown(username, password, ctx)

        # One verification in every branch below, so timing does not reveal the account state.
        password_ok = verify_password(password, user.password_hash)
        if not user.is_active:
            self._fail(ctx, username, "inactive", user)
            raise invalid_credentials()
        if self._lockout.is_locked(user):
            self._fail(ctx, username, "locked", user)
            raise invalid_credentials()
        if not password_ok:
            outcome = self._lockout.register_failure(user, ctx)
            if outcome.locked:
                self._notifier.account_locked(user, permanent=outcome.permanent, until=outcome.until)
            self._fail(ctx, username, "bad_password", user, locked=outcome.locked)
            raise invalid_credentials()

        self._lockout.register_success(user)
        now = self._clock.now()
        if user.password_expires_at is not None and now >= user.password_expires_at:
            user.must_change_password = True
        token, row = self._sessions.create(ctx, user_id=user.id)
        actor = Actor(kind="service" if user.is_service else "user", name=user.username, role=user.role.name,
                      user_id=user.id)
        self._audit.record("auth.login", ctx.with_actor(actor), object_type="user", object_id=user.id)
        return LoginResult(token=token, session=row, user=user)

    def _login_unknown(self, username: str, password: str, ctx: RequestContext) -> LoginResult:
        """No such user: the owner path (if available) or a dummy verification. Same cost, same answer."""
        if self._owner.verify(username, password, ctx.source_ip):
            token, row = self._sessions.create(ctx, user_id=None, is_owner=True)
            owner_ctx = ctx.with_actor(Actor(kind="owner", name="System"))
            self._audit.owner_only("owner.login", owner_ctx)  # OWN-009: no normal audit entry
            return LoginResult(token=token, session=row, user=None)
        self._fail(ctx, username, "unknown_user", None)
        raise invalid_credentials()

    def _fail(self, ctx: RequestContext, username: str, reason: str, user: User | None, locked: bool = False) -> None:
        self._audit.record(
            "auth.login_failed", ctx, object_type="user", object_id=user.id if user else "",
            result="failure", reason=reason, details={"username": username, "locked": locked},
        )

    def logout(self, session: SessionRecord, ctx: RequestContext) -> None:
        self._sessions.revoke(session)
        if not ctx.actor.is_owner:
            self._audit.record("auth.logout", ctx, object_type="user", object_id=ctx.actor.user_id or "")

    def change_password(self, user: User, session: SessionRecord, current: str, new: str,
                        ctx: RequestContext) -> None:
        """IDN-001, PWD-038: voluntary, expired and forced changes all come through here."""
        if not verify_password(current, user.password_hash):
            outcome = self._lockout.register_failure(user, ctx)
            if outcome.locked:
                self._notifier.account_locked(user, permanent=outcome.permanent, until=outcome.until)
            self._audit.record("user.password_change_failed", ctx, object_type="user", object_id=user.id,
                               result="failure", reason="current_password_invalid", details={"locked": outcome.locked})
            raise invalid("password.current_invalid")
        now = self._clock.now()
        expired = user.password_expires_at is not None and now >= user.password_expires_at
        voluntary = not user.must_change_password and not expired
        self._credentials.set_password(user, new, admin_set=False, voluntary=voluntary, must_change_next=False)
        self._sessions.revoke_user_sessions(user.id, except_id=session.id)
        self._accounts.mark_changed(user.username)
        self._notifier.password_changed(user)
        self._audit.record("user.password_changed", ctx, object_type="user", object_id=user.id,
                           details={"forced": not voluntary})


def require_user(user: User | None) -> User:
    if user is None:
        raise forbidden("owner_has_no_password")
    return user
