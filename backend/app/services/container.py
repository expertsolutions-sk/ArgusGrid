"""Wires the services for one unit of work (SOL-005: dependencies are passed in, not opened inside)."""
from __future__ import annotations

from functools import cached_property

from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.config import AppConfig
from app.core.crypto import SecretBox
from app.services.accounts_file import AccountsFile
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.bootstrap_service import BootstrapService
from app.services.credential_service import CredentialService
from app.services.airspace import AirspaceService
from app.services.asset_service import AssetService
from app.services.audit_query import AuditQuery
from app.services.device_credentials import DeviceCredentialService, ReplayCache
from app.services.email_settings import EmailSettingsService
from app.services.incident_service import IncidentService, RunReport
from app.services.intel_service import IntelService
from app.services.mail_service import ExpiryNotifier, MailService, MailTransport, SmtpTransport, TemplateService
from app.services.notifications import SecurityNotifier
from app.services.role_admin_service import RoleAdminService
from app.services.user_service import UserService
from app.services.lockout_policy import LockoutSettingsService
from app.services.lockout_service import LockoutService
from app.services.owner_service import OwnerService
from app.services.policy_service import PasswordPolicyService
from app.services.role_service import RoleService
from app.services.session_service import SessionPolicyService, SessionService
from app.services.settings_store import SettingsStore
from app.services.stream import StreamHub
from app.services.profile import Profile, build_profile
from app.services.telemetry_service import TelemetryStore


class Services:
    def __init__(self, session: Session, clock: Clock, config: AppConfig,
                 transport: MailTransport | None = None, replay: ReplayCache | None = None,
                 hub: StreamHub | None = None) -> None:
        self._replay = replay
        self.hub = hub or StreamHub()
        self.session = session
        self.clock = clock
        self.config = config
        self.transport: MailTransport = transport or SmtpTransport()

    @cached_property
    def store(self) -> SettingsStore:
        return SettingsStore(self.session, self.clock)

    @cached_property
    def policy(self) -> PasswordPolicyService:
        return PasswordPolicyService(self.store)

    @cached_property
    def audit(self) -> AuditService:
        return AuditService(self.session, self.clock)

    @cached_property
    def credentials(self) -> CredentialService:
        return CredentialService(self.session, self.clock, self.policy)

    @cached_property
    def lockout_settings(self) -> LockoutSettingsService:
        return LockoutSettingsService(self.store)

    @cached_property
    def session_policy(self) -> SessionPolicyService:
        return SessionPolicyService(self.store)

    @cached_property
    def sessions(self) -> SessionService:
        return SessionService(self.session, self.clock, self.session_policy)

    @cached_property
    def roles(self) -> RoleService:
        return RoleService(self.session)

    @cached_property
    def lockout(self) -> LockoutService:
        return LockoutService(self.session, self.clock, self.lockout_settings, self.audit, self.credentials)

    @cached_property
    def owner(self) -> OwnerService:
        return OwnerService(self.session, self.clock, self.store, self.config.owner_file)

    @cached_property
    def accounts(self) -> AccountsFile:
        return AccountsFile(self.config.accounts_file)

    @cached_property
    def box(self) -> SecretBox:
        return SecretBox(self.config.secret_key_file)

    @cached_property
    def email_settings(self) -> EmailSettingsService:
        return EmailSettingsService(self.store, self.box)

    @cached_property
    def templates(self) -> TemplateService:
        return TemplateService(self.session, self.clock)

    @cached_property
    def mail(self) -> MailService:
        return MailService(self.session, self.clock, self.templates, self.email_settings, self.box)

    @cached_property
    def expiry_notifier(self) -> ExpiryNotifier:
        return ExpiryNotifier(self.session, self.clock, self.policy, self.mail)

    @cached_property
    def notifier(self) -> SecurityNotifier:
        return SecurityNotifier(self.session, self.clock, self.mail, self.lockout_settings)

    @cached_property
    def auth(self) -> AuthService:
        return AuthService(self.session, self.clock, self.sessions, self.lockout, self.audit, self.owner,
                           self.credentials, self.accounts, self.notifier)

    @cached_property
    def users(self) -> UserService:
        return UserService(self.session, self.clock, self.roles, self.credentials, self.lockout, self.audit,
                           self.mail, self.notifier)

    @cached_property
    def role_admin(self) -> RoleAdminService:
        return RoleAdminService(self.session, self.clock, self.audit)

    @cached_property
    def assets(self) -> AssetService:
        return AssetService(self.session, self.clock, self.audit)

    @cached_property
    def devices(self) -> DeviceCredentialService:
        return DeviceCredentialService(self.session, self.clock, self.box, self.audit, self._replay)

    @cached_property
    def intel(self) -> IntelService:
        return IntelService(self.session, self.clock, self.store, self.audit, self.mail,
                            offline_forced=self.profile.offline_only)

    @cached_property
    def profile(self) -> Profile:
        return build_profile(self.config.profile, self.config.marking)

    @cached_property
    def incidents(self) -> IncidentService:
        return IncidentService(self.session, self.clock, self.audit, self.mail, self.telemetry, self.intel)

    def publish_incidents(self, report: RunReport) -> None:
        """Push created and changed incidents to the live stream."""
        codes = self.incidents._codes()  # noqa: SLF001
        for inc in [*report.created, *report.updated]:
            self.hub.publish({"type": "incident", "created": inc in report.created,
                              "incident": self.incidents.dto(inc, codes=codes)})

    @cached_property
    def airspace(self) -> AirspaceService:
        return AirspaceService(self.store)

    @cached_property
    def telemetry(self) -> TelemetryStore:
        return TelemetryStore(self.session, self.clock, self.airspace,
                              default_retention_days=self.profile.telemetry_retention_days)

    @cached_property
    def audit_query(self) -> AuditQuery:
        return AuditQuery(self.session)

    @cached_property
    def bootstrap(self) -> BootstrapService:
        return BootstrapService(self.session, self.clock, self.store, self.policy, self.credentials,
                                self.lockout_settings, self.session_policy, self.roles, self.audit,
                                self.accounts, self.config.owner_file)
