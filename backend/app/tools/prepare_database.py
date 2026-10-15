"""Create or upgrade the schema and seed first-run data. Safe to run on every start (rules/01, DEP-040).

Usage (from the backend directory):  python -m app.tools.prepare_database [--profile standard|minimal]
The initial administrator password is printed once, only when the account is created.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

from app.core.clock import Clock
from app.core.config import BACKEND_DIR, AppConfig, load_config
from app.core.context import system_context
from app.core.db import Database
from app.services.bootstrap_service import DEFAULT_ADMIN_USERNAME, BootstrapResult
from app.services.container import Services


def upgrade_schema(config: AppConfig) -> None:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", config.database_url.replace("%", "%%"))
    command.upgrade(cfg, "head")


def prepare(config: AppConfig, profile: str = "standard", admin_username: str = DEFAULT_ADMIN_USERNAME,
            clock: Clock | None = None) -> BootstrapResult:
    upgrade_schema(config)
    db = Database(config.database_url)
    try:
        with db.transaction() as session:
            services = Services(session, clock or Clock(), config)
            return services.bootstrap.run(
                password_profile=profile, admin_username=admin_username, ctx=system_context("cli")
            )
    finally:
        db.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="standard", choices=["standard", "minimal"])
    parser.add_argument("--admin-username", default=DEFAULT_ADMIN_USERNAME)
    args = parser.parse_args(argv)
    config = load_config()
    result = prepare(config, args.profile, args.admin_username)
    print(f"Database ready (installation {result.installation_id}).")
    if result.initial_admin_created:
        print("Initial administrator created. Shown once; also saved to the ignored file "
              f"{Path(config.accounts_file)}:")
        print(f"  user name: {result.initial_admin_username}")
        print(f"  password:  {result.initial_admin_password}")
        print("The password must be changed at the first login.")
    else:
        print("Initial administrator already exists; nothing was changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
