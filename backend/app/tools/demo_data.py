"""Demo data commands: create, reset, delete (DEP-050).

Usage (from the backend directory):  python -m app.tools.demo_data create|reset|delete
"""
from __future__ import annotations

import argparse
import sys

from app.core.clock import Clock
from app.core.config import load_config
from app.core.db import Database
from app.services.container import Services
from app.services.demo_service import DemoService, write_secrets_file


def run(action: str) -> int:
    config = load_config()
    db = Database(config.database_url)
    try:
        with db.transaction() as session:
            services = Services(session, Clock(), config)
            demo = DemoService(session, services.clock, services.box, services.audit, services.intel)
            if action in ("delete", "reset"):
                removed = demo.delete()
                print(f"Removed demo data: {removed.assets} assets, {removed.zones} zones.")
                if action == "delete":
                    return 0
                session.flush()
            report = demo.create()
            print(f"Demo data: {report.zones} zones, {report.assets} assets, {report.relations} relations, "
                  f"{report.credentials} device credentials created.")
            if report.secrets:
                target = config.data_dir / "demo-devices.txt"
                write_secrets_file(target, report.secrets, "http://127.0.0.1:8000")
                print(f"Device secrets saved to {target} (ignored by Git). They are not shown again.")
            elif action == "create":
                print("Nothing new to create (already present).")
        return 0
    finally:
        db.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["create", "reset", "delete"])
    return run(parser.parse_args(argv).action)


if __name__ == "__main__":
    sys.exit(main())
