"""Request and response models. Kept apart from routers so they can be reused (SOL-001)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(_Strict):
    username: str = Field(max_length=128)
    password: str = Field(max_length=1024)


class ChangePasswordRequest(_Strict):
    current_password: str = Field(max_length=1024)
    new_password: str = Field(max_length=1024)


class SettingsBody(BaseModel):
    """Policy documents are validated by their own services; here only the shape is accepted."""

    model_config = ConfigDict(extra="allow")


class UserInfo(BaseModel):
    username: str
    full_name: str
    role: str
    email: str = ""


class ProfileInfo(BaseModel):
    name: str = "civil"
    marking: str = ""


class SessionInfo(BaseModel):
    authenticated: bool
    user: UserInfo | None = None
    csrf_token: str | None = None
    must_change_password: bool = False
    capabilities: list[str] = []
    dev_loginless: bool = False
    dev_banner: str = ""
    profile: ProfileInfo = ProfileInfo()
    password_expires_at: str | None = None


class GeneratedPassword(BaseModel):
    password: str


class PolicyEnvelope(BaseModel):
    policy: dict[str, Any]
    limits: dict[str, Any] = {}
