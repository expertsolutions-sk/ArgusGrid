"""First-run initialisation: roles, default settings, installation id, initial administrator (rules/19)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.context import RequestContext, system_context
from app.core.permissions import ADMINISTRATOR
from app.models.identity import Role, User
from app.services.accounts_file import AccountsFile
from app.services.audit_service import AuditService
from app.services.credential_service import CredentialService
from app.services.lockout_policy import LockoutSettingsService
from app.services.owner_service import INSTALLATION_KEY, read_sealed_file
from app.services.policy_service import PasswordPolicyService
from app.services.role_service import RoleService
from app.services.session_service import SessionPolicyService
from app.services.settings_store import SettingsStore

DEFAULT_ADMIN_USERNAME = "sysadmin"


@dataclass
class BootstrapResult:
    initial_admin_created: bool = False
    initial_admin_username: str = ""
    initial_admin_password: str = ""  # shown once on the console by the caller, never logged
    installation_id: str = ""


class BootstrapService:
    def __init__(
        self,
        session: Session,
        clock: Clock,
        store: SettingsStore,
        policy: PasswordPolicyService,
        credentials: CredentialService,
        lockout_settings: LockoutSettingsService,
        session_policy: SessionPolicyService,
        roles: RoleService,
        audit: AuditService,
        accounts: AccountsFile,
        sealed_owner_path: object,
    ) -> None:
        self._session = session
        self._clock = clock
        self._store = store
        self._policy = policy
        self._credentials = credentials
        self._lockout_settings = lockout_settings
        self._session_policy = session_policy
        self._roles = roles
        self._audit = audit
        self._accounts = accounts
        self._sealed_path = sealed_owner_path

    def run(self, *, password_profile: str = "standard", admin_username: str = DEFAULT_ADMIN_USERNAME,
            ctx: RequestContext | None = None) -> BootstrapResult:
        ctx = ctx or system_context("cli")
        result = BootstrapResult()
        self._roles.seed_defaults()
        self._policy.seed_profile(password_profile)
        self._lockout_settings.seed_defaults()
        self._session_policy.seed_defaults()
        result.installation_id = self._ensure_installation_id()
        self._ensure_initial_admin(admin_username, ctx, result)
        return result

    def _ensure_installation_id(self) -> str:
        """The sealed owner file (if present) defines the installation; otherwise a random id is created."""
        current = self._store.get(INSTALLATION_KEY)
        if current and current.get("id"):
            return str(current["id"])
        sealed = read_sealed_file(self._sealed_path)  # type: ignore[arg-type]
        installation_id = sealed.installation_id if sealed else str(uuid.uuid4())
        self._store.put(INSTALLATION_KEY, {"id": installation_id})
        return installation_id

    def _ensure_initial_admin(self, username: str, ctx: RequestContext, result: BootstrapResult) -> None:
        """IDN-011: only when no administrator exists. Later runs never overwrite it."""
        admin_role = self._roles.by_name(ADMINISTRATOR)
        assert admin_role is not None
        count = self._session.execute(
            select(func.count()).select_from(User).where(User.role_id == admin_role.id)
        ).scalar_one()
        if count > 0:
            return
        password = self._credentials.generate_password(username)
        user = User(
            username=username, username_key=username.lower(), email="", full_name="System administrator",
            role_id=admin_role.id, password_hash="", must_change_password=True, is_active=True,
            created_at=self._clock.now(), created_by="system",
        )
        self._credentials.apply_to_new_user(user, password, must_change=True)
        self._session.add(user)
        self._session.flush()
        self._accounts.write_initial(username, password)
        self._audit.record("user.create", ctx, object_type="user", object_id=user.id,
                           details={"username": username, "role": ADMINISTRATOR, "initial": True})
        result.initial_admin_created = True
        result.initial_admin_username = username
        result.initial_admin_password = password


def role_exists(session: Session, name: str) -> bool:
    return session.execute(select(Role.id).where(Role.name == name)).first() is not None
