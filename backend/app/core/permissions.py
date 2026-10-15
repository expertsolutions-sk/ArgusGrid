"""Capability registry and default roles. The single source of capability names (SOL-007).

Roles and their capabilities are stored in the database and editable at runtime (IDN-004).
The defaults below are only used to seed an empty database and to top up the Administrator role.
"""
from __future__ import annotations

ADMINISTRATOR = "Administrator"
DEVICE_AGENT = "Device Agent"


class Cap:
    # users
    USER_VIEW = "user.view"
    USER_CREATE = "user.create"
    USER_EDIT = "user.edit"
    USER_DELETE = "user.delete"
    USER_LOCK = "user.lock"
    USER_UNLOCK = "user.unlock"
    USER_RESET_PASSWORD = "user.reset_password"
    USER_ROLE_ASSIGN = "user.role.assign"
    USER_VIEW_ADMINS = "user.view_admins"
    # roles
    ROLE_VIEW = "role.view"
    ROLE_MANAGE = "role.manage"
    # policies
    POLICY_PASSWORD_VIEW = "policy.password.view"
    POLICY_PASSWORD_EDIT = "policy.password.edit"
    POLICY_LOCKOUT_VIEW = "policy.lockout.view"
    POLICY_LOCKOUT_EDIT = "policy.lockout.edit"
    POLICY_SESSION_VIEW = "policy.session.view"
    POLICY_SESSION_EDIT = "policy.session.edit"
    # e-mail
    EMAIL_VIEW = "settings.email.view"
    EMAIL_EDIT = "settings.email.edit"
    EMAIL_TEMPLATES_EDIT = "settings.email.templates.edit"
    # audit
    AUDIT_VIEW = "audit.view"
    AUDIT_EXPORT = "audit.export"
    # assets
    ASSET_VIEW = "asset.view"
    ASSET_CREATE = "asset.create"
    ASSET_EDIT = "asset.edit"
    ASSET_DELETE = "asset.delete"
    ASSET_CREDENTIAL_ROTATE = "asset.credential.rotate"
    # intelligence
    INTEL_VIEW = "intel.view"
    INTEL_ACK = "intel.ack"
    INTEL_SOURCES_MANAGE = "intel.sources.manage"
    # incidents
    INCIDENT_VIEW = "incident.view"
    INCIDENT_TRIAGE = "incident.triage"
    INCIDENT_ESCALATE = "incident.escalate"
    INCIDENT_CLOSE = "incident.close"
    # simulation and devices
    SIMULATION_RUN = "simulation.run"
    SENSOR_INGEST = "sensor.ingest"


ALL_CAPABILITIES: tuple[str, ...] = tuple(
    value for name, value in vars(Cap).items() if not name.startswith("_") and isinstance(value, str)
)

# Capabilities that only a device (service) account may hold. Administrator never gets them.
DEVICE_ONLY: frozenset[str] = frozenset({Cap.SENSOR_INGEST})

_VIEW_POLICIES = [Cap.POLICY_PASSWORD_VIEW, Cap.POLICY_LOCKOUT_VIEW, Cap.POLICY_SESSION_VIEW]


class RoleDefault:
    def __init__(self, name: str, level: int, description: str, caps: list[str]) -> None:
        self.name = name
        self.level = level
        self.description = description
        self.caps = frozenset(caps)


DEFAULT_ROLES: tuple[RoleDefault, ...] = (
    RoleDefault(ADMINISTRATOR, 100, "System administration: users, roles, policies, settings",
                [c for c in ALL_CAPABILITIES if c not in DEVICE_ONLY]),
    RoleDefault("SOC Manager", 80, "Leads the SOC: users (limited), incidents, simulation",
                [Cap.USER_VIEW, Cap.USER_CREATE, Cap.USER_EDIT, Cap.USER_UNLOCK, Cap.ROLE_VIEW, *_VIEW_POLICIES,
                 Cap.AUDIT_VIEW, Cap.EMAIL_VIEW, Cap.ASSET_VIEW, Cap.INTEL_VIEW, Cap.INTEL_ACK,
                 Cap.INCIDENT_VIEW, Cap.INCIDENT_TRIAGE, Cap.INCIDENT_ESCALATE, Cap.INCIDENT_CLOSE,
                 Cap.SIMULATION_RUN]),
    RoleDefault("SOC Analyst", 60, "Investigates and escalates incidents",
                [Cap.ASSET_VIEW, Cap.INTEL_VIEW, Cap.INTEL_ACK, Cap.INCIDENT_VIEW, Cap.INCIDENT_TRIAGE,
                 Cap.INCIDENT_ESCALATE]),
    RoleDefault("SOC Operator", 40, "Watches the dashboard and triages incidents",
                [Cap.ASSET_VIEW, Cap.INTEL_VIEW, Cap.INCIDENT_VIEW, Cap.INCIDENT_TRIAGE]),
    RoleDefault("OT Asset Engineer", 40, "Maintains the asset registry and device credentials",
                [Cap.ASSET_VIEW, Cap.ASSET_CREATE, Cap.ASSET_EDIT, Cap.ASSET_DELETE, Cap.ASSET_CREDENTIAL_ROTATE,
                 Cap.INTEL_VIEW, Cap.INCIDENT_VIEW]),
    RoleDefault("Auditor", 30, "Read-only access to audit and configuration",
                [Cap.USER_VIEW, Cap.AUDIT_VIEW, Cap.AUDIT_EXPORT, *_VIEW_POLICIES, Cap.EMAIL_VIEW,
                 Cap.ASSET_VIEW, Cap.INTEL_VIEW, Cap.INCIDENT_VIEW]),
    RoleDefault(DEVICE_AGENT, 10, "Service account of a sensor or gateway (ingest only)",
                [Cap.SENSOR_INGEST]),
)
