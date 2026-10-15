"""Simulator runner: signs and posts the scenario events to the real ingestion API (IDN-014).

It reads the device keys from the ignored file written by the demo data command and never prompts.
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

import httpx

from app.core.signing import signed_headers
from app.simulator.scenario import END_TIME, Scenario

INGEST_PATH = "/api/v1/ingest/events"


class Poster(Protocol):
    def __call__(self, path: str, content: bytes, headers: dict[str, str]) -> int: ...


@dataclass(frozen=True)
class DeviceKey:
    key_id: str
    secret: str


def load_credentials(path: Path) -> dict[str, DeviceKey]:
    """Lines: `<asset code> <key id> <secret>`. Lines starting with # are comments."""
    keys: dict[str, DeviceKey] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        code, key_id, secret = line.split()
        keys[code] = DeviceKey(key_id, secret)
    return keys


def http_poster(base_url: str, timeout: float = 10.0) -> Poster:
    client = httpx.Client(base_url=base_url, timeout=timeout)

    def post(path: str, content: bytes, headers: dict[str, str]) -> int:
        return client.post(path, content=content, headers=headers).status_code

    return post


@dataclass
class RunStats:
    sent_events: int = 0
    requests: int = 0
    failed_requests: int = 0
    unknown_devices: set[str] | None = None


def run(
    keys: dict[str, DeviceKey],
    poster: Poster,
    *,
    speed: float = 1.0,
    tick_s: float = 1.0,
    start_at: float = 0.0,
    until: float | None = None,
    now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    scenario: Scenario | None = None,
    on_progress: Callable[[float, int], None] | None = None,
) -> RunStats:
    """Play the scenario. `speed` multiplies simulated time; `sleep=lambda s: None` runs as fast as possible."""
    import json

    scenario = scenario or Scenario()
    stats = RunStats(unknown_devices=set())
    end = END_TIME if until is None else until
    t = start_at
    while t <= end:
        batches: dict[str, list[dict]] = defaultdict(list)
        for ev in scenario.events_until(t):
            if ev.device not in keys:
                stats.unknown_devices.add(ev.device)  # type: ignore[union-attr]
                continue
            batches[ev.device].append(ev.body)
        for device, events in batches.items():
            body = json.dumps({"events": events}, separators=(",", ":")).encode("utf-8")
            key = keys[device]
            headers = signed_headers(key.key_id, key.secret, "POST", INGEST_PATH, int(now()), body)
            headers["Content-Type"] = "application/json"
            status = poster(INGEST_PATH, body, headers)
            stats.requests += 1
            stats.sent_events += len(events)
            if status != 200:
                stats.failed_requests += 1
        if on_progress is not None:
            on_progress(t, stats.sent_events)
        t += tick_s
        sleep(tick_s / speed)
    return stats
