"""Account-security notifications built on the mail outbox (rules/18 section 2: notify the account and,
for an administrator account, the other administrators)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.permissions import ADMINISTRATOR
from app.models.identity import Role, User
from app.services.lockout_policy import LockoutSettingsService
from app.services.mail_service import MailService


class SecurityNotifier:
    def __init__(self, session: Session, clock: Clock, mail: MailService, lockout_settings: LockoutSettingsService) -> None:
        self._s = session
        self._clock = clock
        self._mail = mail
        self._settings = lockout_settings

    def account_locked(self, user: User, *, permanent: bool, until: datetime | None, manual: bool = False) -> None:
        policy = self._settings.get().policy_for(user.role.name)
        if not manual and not policy.notify:
            return
        if manual:
            description = "locked by an administrator"
        elif permanent:
            description = "locked until an administrator unlocks it"
        else:
            description = f"until {until.strftime('%Y-%m-%d %H:%M UTC')}" if until else "temporarily"
        self._mail.queue("user.locked", user, {"lock_description": description})
        if user.role.name == ADMINISTRATOR:
            others = self._s.execute(
                select(User).join(Role, User.role_id == Role.id)
                .where(Role.name == ADMINISTRATOR, User.is_active.is_(True), User.id != user.id, User.email != "")
            ).scalars()
            for admin in others:
                self._mail.queue("admin.user_locked", admin,
                                 {"locked_username": user.username, "lock_description": description})

    def password_changed(self, user: User) -> None:
        self._mail.queue("user.password_changed", user,
                         {"changed_at": self._clock.now().strftime("%Y-%m-%d %H:%M UTC")})
