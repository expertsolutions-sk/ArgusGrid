"""Application configuration: one place that reads the environment (rules/01 configuration hierarchy)."""
from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class ConfigError(RuntimeError):
    """Raised when the configuration is unusable. The message never contains secrets."""


@dataclass(frozen=True)
class AppConfig:
    environment: str  # development | production | test
    data_dir: Path
    config_dir: Path
    database_url: str
    secure_cookies: bool
    bind_host: str
    dev_loginless: bool
    dev_loginless_role: str
    run_workers: bool = True
    profile: str = "civil"  # civil | defense (ARG-021)
    marking: str | None = None  # None = the default marking of the profile

    @property
    def accounts_file(self) -> Path:
        return self.data_dir / "accounts.txt"

    @property
    def owner_file(self) -> Path:
        return self.config_dir / "owner.sealed"

    @property
    def secret_key_file(self) -> Path:
        """Key for encrypting stored secrets (SMTP password, queued credentials). Ignored by Git."""
        return self.data_dir / "secret.key"


def _read_database_url(data_dir: Path) -> str:
    url = os.environ.get("ARGUS_DATABASE_URL", "").strip()
    if url:
        return url
    url_file = data_dir / "database.url"
    if url_file.is_file():
        return url_file.read_text(encoding="utf-8").strip()
    raise ConfigError("No database configured: set ARGUS_DATABASE_URL or create data/database.url")


def load_config(**overrides: object) -> AppConfig:
    """Build the configuration from the environment. Keyword arguments override single fields (tests)."""
    environment = os.environ.get("ARGUS_ENV", "production").strip().lower()
    data_dir = Path(os.environ.get("ARGUS_DATA_DIR", str(BACKEND_DIR / "data")))
    config_dir = Path(os.environ.get("ARGUS_CONFIG_DIR", str(BACKEND_DIR / "config")))
    bind_host = os.environ.get("ARGUS_BIND_HOST", "127.0.0.1").strip()

    # DEV-001 / DEV-007: the flag lives in the development-only module (DEV-005, DEV-006); without the module,
    # as in every package, there is no flag and loginless mode cannot be switched on.
    dev_loginless, dev_role = False, "Administrator"
    try:
        from app import dev_loginless as dev_module
    except ImportError:
        pass
    else:
        dev_loginless, dev_role = dev_module.read_flag(os.environ, environment)
    if dev_loginless and bind_host not in LOOPBACK_HOSTS:
        raise ConfigError("Loginless mode requires a loopback bind address")  # DEV-002

    profile = os.environ.get("ARGUS_PROFILE", "civil").strip().lower()
    if profile not in ("civil", "defense"):
        raise ConfigError("ARGUS_PROFILE must be civil or defense")
    marking = os.environ.get("ARGUS_MARKING")

    cfg = AppConfig(
        environment=environment,
        data_dir=data_dir,
        config_dir=config_dir,
        database_url=str(overrides.get("database_url") or _read_database_url(data_dir)),
        secure_cookies=os.environ.get("ARGUS_SECURE_COOKIES", "0").strip() == "1",
        bind_host=bind_host,
        dev_loginless=dev_loginless,
        dev_loginless_role=dev_role,
        run_workers=os.environ.get("ARGUS_WORKERS", "1").strip() == "1",
        profile=profile,
        marking=marking,
    )
    clean = {k: v for k, v in overrides.items() if k != "database_url"}
    return replace(cfg, **clean) if clean else cfg
