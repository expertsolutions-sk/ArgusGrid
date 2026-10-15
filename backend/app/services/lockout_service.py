"""Applies the lockout policy to users (rules/18): counting, locking, release, manual unlock."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.context import RequestContext
from app.core.permissions import ADMINISTRATOR
from app.models.identity import FailedLogin, SessionRecord, User
from app.services.audit_service import AuditService
from app.services.credential_service import CredentialService
from app.services.lockout_policy import LockoutPolicy, LockoutSettingsService


@dataclass
class LockOutcome:
    locked: bool
    permanent: bool = False
    until: datetime | None = None
    suppressed: bool = False  # lock skipped because of exempt_last_administrator


@dataclass
class UnlockOutcome:
    after_unlock: str
    temporary_password: str | None = None  # only for reset_password; the caller sends it and drops it


class LockoutService:
    def __init__(
        self,
        session: Session,
        clock: Clock,
        settings: LockoutSettingsService,
        audit: AuditService,
        credentials: CredentialService,
    ) -> None:
        self._session = session
        self._clock = clock
        self._settings = settings
        self._audit = audit
        self._credentials = credentials

    # -- state --------------------------------------------------------------------------------------
    def is_locked(self, user: User) -> bool:
        """True while an active lock applies. Also releases an expired timed lock."""
        now = self._clock.now()
        if user.lock_permanent:
            return True
        if user.locked_until is None:
            return False
        if user.locked_until > now:
            return True
        # Timed lock expired: release automatically and reset the counter (LCK mode auto_unlock).
        user.locked_until = None
        user.lock_reason = ""
        self._clear_failures(user.id)
        return False

    def describe_lock(self, user: User) -> dict[str, object]:
        """LCK-014: temporary and permanent locks are distinguishable, with the release time."""
        if user.lock_permanent:
            return {"state": "locked_permanent", "manual": user.lock_manual, "until": None}
        if user.locked_until is not None and user.locked_until > self._clock.now():
            return {"state": "locked_temporary", "manual": user.lock_manual, "until": user.locked_until.isoformat()}
        return {"state": "active", "manual": False, "until": None}

    # -- failures and success -----------------------------------------------------------------------
    def register_failure(self, user: User, ctx: RequestContext) -> LockOutcome:
        settings = self._settings.get()
        policy = settings.policy_for(user.role.name)
        now = self._clock.now()
        self._session.add(FailedLogin(user_id=user.id, at=now, source_ip=ctx.source_ip))
        self._session.flush()
        window_start = now - timedelta(minutes=policy.window_minutes)
        count = self._session.execute(
            select(func.count()).select_from(FailedLogin).where(
                FailedLogin.user_id == user.id, FailedLogin.at >= window_start
            )
        ).scalar_one()
        if count < policy.threshold:
            return LockOutcome(locked=False)

        if settings.exempt_last_administrator and self._is_last_usable_administrator(user):
            self._audit.record(
                "auth.lock_suppressed", ctx, object_type="user", object_id=user.id, result="info",
                reason="exempt_last_administrator", details={"failed_attempts": count},
            )
            return LockOutcome(locked=False, suppressed=True)

        return self._lock(user, policy, ctx, manual=False, reason="failed_attempts", failed_attempts=count)

    def register_success(self, user: User) -> None:
        user.lock_cycles = 0
        user.locked_until = None
        user.lock_permanent = False
        user.lock_manual = False
        user.lock_reason = ""
        user.last_login_at = self._clock.now()
        self._clear_failures(user.id)

    # -- manual lock and unlock ---------------------------------------------------------------------
    def lock_manually(self, target: User, ctx: RequestContext, reason: str = "") -> None:
        """LCK-014/LCK-017: a manual lock is permanent and distinguishable from an automatic one."""
        target.lock_permanent = True
        target.locked_until = None
        target.lock_manual = True
        target.lock_reason = reason[:255]
        self._revoke_sessions(target)
        self._audit.record("user.lock", ctx, object_type="user", object_id=target.id, reason=reason,
                           details={"mode": "manual"})

    def unlock(self, target: User, ctx: RequestContext) -> UnlockOutcome:
        """LCK-015: self-unlock is impossible. Runs the configured after-unlock action (LCK-016)."""
        actor = ctx.actor
        if actor.user_id is not None and actor.user_id == target.id:
            raise PermissionError("self_unlock")
        policy = self._settings.get().policy_for(target.role.name)
        if not actor.is_owner and actor.role not in policy.unlockers:
            raise PermissionError("not_an_unlocker")

        target.locked_until = None
        target.lock_permanent = False
        target.lock_manual = False
        target.lock_reason = ""
        target.lock_cycles = 0
        self._clear_failures(target.id)
        if policy.revoke_sessions:
            self._revoke_sessions(target)

        outcome = UnlockOutcome(after_unlock=policy.after_unlock)
        if policy.after_unlock == "require_password_change":
            target.must_change_password = True
        elif policy.after_unlock == "reset_password":
            temporary = self._credentials.generate_password(target.username)
            self._credentials.set_password(target, temporary, admin_set=True, must_change_next=True)
            self._revoke_sessions(target)
            outcome.temporary_password = temporary
        self._audit.record(
            "user.unlock", ctx, object_type="user", object_id=target.id,
            details={"after_unlock": policy.after_unlock},
        )
        return outcome

    # -- helpers ------------------------------------------------------------------------------------
    def _lock(self, user: User, policy: LockoutPolicy, ctx: RequestContext, *, manual: bool, reason: str,
              failed_attempts: int) -> LockOutcome:
        cycle = user.lock_cycles + 1
        permanent = policy.mode == "permanent" or (
            policy.cycles_before_permanent is not None and cycle > policy.cycles_before_permanent
        )
        until: datetime | None = None
        if not permanent:
            if policy.mode == "escalating":
                minutes = policy.durations_minutes[min(cycle - 1, len(policy.durations_minutes) - 1)]
            else:
                minutes = policy.durations_minutes[0]
            until = self._clock.now() + timedelta(minutes=minutes)
        user.lock_cycles = cycle
        user.lock_permanent = permanent
        user.locked_until = until
        user.lock_manual = manual
        user.lock_reason = reason
        self._clear_failures(user.id)
        if policy.revoke_sessions:
            self._revoke_sessions(user)
        self._audit.record(
            "user.locked", ctx, object_type="user", object_id=user.id, result="info", reason=reason,
            details={"mode": policy.mode, "cycle": cycle, "permanent": permanent,
                     "until": until.isoformat() if until else None, "failed_attempts": failed_attempts},
        )
        return LockOutcome(locked=True, permanent=permanent, until=until)

    def _is_last_usable_administrator(self, user: User) -> bool:
        if user.role.name != ADMINISTRATOR:
            return False
        now = self._clock.now()
        others = self._session.execute(
            select(func.count()).select_from(User).where(
                User.id != user.id,
                User.is_active.is_(True),
                User.lock_permanent.is_(False),
                (User.locked_until.is_(None)) | (User.locked_until <= now),
                User.role.has(name=ADMINISTRATOR),
            )
        ).scalar_one()
        return others == 0

    def _clear_failures(self, user_id: int) -> None:
        self._session.execute(delete(FailedLogin).where(FailedLogin.user_id == user_id))

    def _revoke_sessions(self, user: User) -> None:
        self._session.execute(
            update(SessionRecord)
            .where(SessionRecord.user_id == user.id, SessionRecord.revoked_at.is_(None))
            .values(revoked_at=self._clock.now())
        )
