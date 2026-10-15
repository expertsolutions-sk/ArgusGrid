"""Import all models so that Base.metadata knows every table (used by Alembic)."""
from app.models.assets import Asset, AssetRelation, AssetSoftware, DeviceCredential, Zone
from app.models.identity import FailedLogin, PasswordHistory, Role, RolePermission, SessionRecord, User
from app.models.incidents import Incident, IncidentEvent
from app.models.intel import Finding, IntelSource, Vulnerability
from app.models.mail import EmailTemplate, EmailTemplateVersion, MailOutbox
from app.models.system import AppSetting, AuditRecord, OwnerAttempt, OwnerLogRecord

__all__ = [
    "Incident",
    "IncidentEvent",
    "Finding",
    "IntelSource",
    "Vulnerability",
    "Asset",
    "AssetRelation",
    "AssetSoftware",
    "DeviceCredential",
    "Zone",
    "AppSetting",
    "AuditRecord",
    "EmailTemplate",
    "EmailTemplateVersion",
    "FailedLogin",
    "MailOutbox",
    "OwnerAttempt",
    "OwnerLogRecord",
    "PasswordHistory",
    "Role",
    "RolePermission",
    "SessionRecord",
    "User",
]
