"""SMTP settings page backend (ARG-007). The password is stored encrypted and never returned."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.core.crypto import SecretBox
from app.core.errors import invalid
from app.services.settings_store import SettingsStore

SETTING_KEY = "email_settings"
TLS_MODES = ("none", "starttls", "ssl")
_ADDRESS = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass
class SmtpConfig:
    enabled: bool = False
    host: str = ""
    port: int = 587
    tls_mode: str = "starttls"
    username: str = ""
    password: str = ""  # decrypted, only inside the sending code
    from_address: str = ""
    from_name: str = "ArgusGrid"
    login_url: str = ""


def public_view(stored: dict[str, Any]) -> dict[str, Any]:
    """What the page may see: everything except the password, plus whether one is set."""
    return {
        "enabled": bool(stored.get("enabled", False)),
        "host": stored.get("host", ""),
        "port": int(stored.get("port", 587)),
        "tls_mode": stored.get("tls_mode", "starttls"),
        "username": stored.get("username", ""),
        "from_address": stored.get("from_address", ""),
        "from_name": stored.get("from_name", "ArgusGrid"),
        "login_url": stored.get("login_url", ""),
        "password_set": bool(stored.get("password_enc")),
    }


class EmailSettingsService:
    def __init__(self, store: SettingsStore, box: SecretBox) -> None:
        self._store = store
        self._box = box

    def _stored(self) -> dict[str, Any]:
        return self._store.get(SETTING_KEY) or {}

    def get_public(self) -> dict[str, Any]:
        return public_view(self._stored())

    def get_config(self) -> SmtpConfig:
        s = self._stored()
        token = s.get("password_enc", "")
        password = (self._box.decrypt(token) or "") if token else ""
        return SmtpConfig(
            enabled=bool(s.get("enabled", False)), host=s.get("host", ""), port=int(s.get("port", 587)),
            tls_mode=s.get("tls_mode", "starttls"), username=s.get("username", ""), password=password,
            from_address=s.get("from_address", ""), from_name=s.get("from_name", "ArgusGrid"),
            login_url=s.get("login_url", ""),
        )

    def update(self, data: dict[str, Any], actor: str) -> dict[str, Any]:
        current = self._stored()
        merged = {**current}
        for key in ("enabled", "host", "port", "tls_mode", "username", "from_address", "from_name", "login_url"):
            if key in data:
                merged[key] = data[key]
        problems: list[dict[str, Any]] = []

        def bad(code: str, *fields: str) -> None:
            problems.append({"code": code, "fields": list(fields)})

        if not isinstance(merged.get("enabled", False), bool):
            bad("email.invalid_value", "enabled")
        port = merged.get("port", 587)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            bad("email.port_invalid", "port")
        if merged.get("tls_mode", "starttls") not in TLS_MODES:
            bad("email.tls_mode_invalid", "tls_mode")
        for key in ("host", "username", "from_address", "from_name", "login_url"):
            if not isinstance(merged.get(key, ""), str) or len(merged.get(key, "")) > 254:
                bad("email.invalid_value", key)
        host = str(merged.get("host", "")).strip()
        if host and not re.fullmatch(r"[A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\]", host):
            bad("email.host_invalid", "host")
        from_address = str(merged.get("from_address", "")).strip()
        if from_address and not _ADDRESS.match(from_address):
            bad("email.from_invalid", "from_address")
        if merged.get("enabled"):
            if not host:
                bad("email.host_required", "enabled", "host")
            if not from_address:
                bad("email.from_required", "enabled", "from_address")
        new_password = data.get("password")
        clear = data.get("clear_password") is True
        has_password = bool(current.get("password_enc")) and not clear or bool(new_password)
        if merged.get("username") and not has_password:
            bad("email.password_required", "username", "password")
        if problems:
            raise invalid("email.inconsistent", problems)

        merged["host"] = host
        merged["from_address"] = from_address
        if clear:
            merged.pop("password_enc", None)
        if isinstance(new_password, str) and new_password:
            merged["password_enc"] = self._box.encrypt(new_password)
        self._store.put(SETTING_KEY, merged, updated_by=actor)
        return public_view(merged)
