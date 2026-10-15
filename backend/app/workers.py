"""Background worker: delivers the outbox and queues password-expiry notices (rules/01 background isolation).

It reads its configuration from the same database as the web application and survives errors.
"""
from __future__ import annotations

import logging
import threading

from app.core.clock import Clock
from app.core.config import AppConfig
from app.core.db import Database
from app.services.container import Services
from app.services.intel_service import Fetcher, HttpFetcher
from app.services.mail_service import MailTransport

log = logging.getLogger("argusgrid.worker")


def run_once(db: Database, clock: Clock, config: AppConfig, transport: MailTransport,
             fetcher: Fetcher | None = None) -> dict[str, int]:
    """One pass: expiry notices first (they enqueue), then delivery. Returns counters for logs and tests."""
    with db.transaction() as session:
        services = Services(session, clock, config, transport)
        queued = services.expiry_notifier.run()
        report = services.mail.send_pending(transport)
        # telemetry housekeeping: prepare the coming days, drop what the retention period has passed
        services.telemetry.ensure_current()
        incidents = services.incidents.run(force=True)
        fetched = services.intel.run_due_sources(fetcher or HttpFetcher())
        # the stream hub is not reachable from here; findings reach the UI on its next refresh
        purged = services.telemetry.purge() if _purge_due(clock) else {}
        return {"expiry_queued": queued, "sent": report.sent, "retry": report.retry, "failed": report.failed,
                "waiting": report.waiting, "intel_sources_run": len(fetched), "incidents_created": len(incidents.created), **purged}


_last_purge: dict[str, object] = {}


def _purge_due(clock: Clock) -> bool:
    """Retention is checked once per day, not on every pass."""
    today = clock.now().date()
    if _last_purge.get("day") == today:
        return False
    _last_purge["day"] = today
    return True


class MailWorker(threading.Thread):
    def __init__(self, db: Database, clock: Clock, config: AppConfig, transport: MailTransport,
                 interval_seconds: float = 30.0, fetcher: Fetcher | None = None) -> None:
        super().__init__(name="argusgrid-mail-worker", daemon=True)
        self._db, self._clock, self._config, self._transport = db, clock, config, transport
        self._fetcher = fetcher
        self._interval = interval_seconds
        self._stop_event = threading.Event()

    def run(self) -> None:
        while not self._stop_event.wait(self._interval):
            try:
                run_once(self._db, self._clock, self._config, self._transport, self._fetcher)
            except Exception:  # keep the worker alive; details go to the log, never to users
                log.exception("mail worker pass failed")

    def stop(self) -> None:
        self._stop_event.set()
