"""Telemetry: validation, classification, partitioned storage, state and retention (ARG-014, ARG-025)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from threading import Lock
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.models.assets import Asset, Zone
from app.services import airspace as air
from app.services.device_credentials import DeviceIdentity

KIND_SCOPE = {
    "rf": "ingest:rf", "radar": "ingest:radar", "eoir": "ingest:eoir", "acoustic": "ingest:acoustic",
    "fence": "ingest:fence", "access": "ingest:access", "weather": "ingest:weather", "cyber": "ingest:cyber",
}
EVENT_TYPES = ("track", "detection", "alarm", "status")
AIRBORNE_KINDS = ("rf", "radar", "eoir", "acoustic")
MAX_BATCH = 100
MAX_PAYLOAD_BYTES = 2048
MAX_AGE = timedelta(hours=1)
MAX_FUTURE = timedelta(minutes=2)
POSITION_MARGIN_M = 2000.0  # the airspace around the site is larger than the site itself
RETENTION_SETTING = "telemetry_retention_days"
DEFAULT_RETENTION_DAYS = 30
ACTIVE_TRACK_WINDOW = timedelta(seconds=90)
ONLINE_WINDOW = timedelta(seconds=120)
_TRACK_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_PARTITION = re.compile(r"^telemetry_events_(\d{8})$")
PRECISE_KINDS = ("radar", "eoir")  # best position quality; RF and acoustic fixes are coarser
_PREPARED_DAYS: set[date] = set()  # partitions known to exist in this process (checked once per day)
_PREPARED_LOCK = Lock()


@dataclass
class IngestResult:
    accepted: int
    rejected: list[dict[str, Any]]
    messages: list[dict[str, Any]]  # what the live stream publishes


def _num(value: Any) -> float | None:
    if value is None or isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


class TelemetryStore:
    def __init__(self, session: Session, clock: Clock, airspace: air.AirspaceService,
                 default_retention_days: int = DEFAULT_RETENTION_DAYS) -> None:
        self._default_retention = default_retention_days
        self._s = session
        self._clock = clock
        self._airspace = airspace

    # -- partitions ---------------------------------------------------------------------------------
    @staticmethod
    def partition_name(day: date) -> str:
        return f"telemetry_events_{day:%Y%m%d}"

    def ensure_partitions(self, start: date, end: date) -> int:
        """Create the daily partitions in [start, end]. A day that already has rows in the default partition
        cannot be carved out; it is skipped and its rows stay readable in the default partition."""
        created = 0
        day = start
        while day <= end:
            with _PREPARED_LOCK:
                known = day in _PREPARED_DAYS
            if not known:
                name = self.partition_name(day)
                nxt = day + timedelta(days=1)
                exists = self._s.execute(text("SELECT to_regclass(:n)"), {"n": name}).scalar_one()
                if exists is None:
                    try:
                        with self._s.begin_nested():
                            self._s.execute(text(
                                f"CREATE TABLE {name} PARTITION OF telemetry_events "
                                f"FOR VALUES FROM ('{day.isoformat()}') TO ('{nxt.isoformat()}')"))
                        created += 1
                    except Exception:  # rows for that day already sit in the default partition
                        pass
                with _PREPARED_LOCK:
                    _PREPARED_DAYS.add(day)
            day += timedelta(days=1)
        return created

    def ensure_current(self) -> None:
        today = self._clock.now().astimezone(timezone.utc).date()
        self.ensure_partitions(today - timedelta(days=1), today + timedelta(days=2))

    def list_partitions(self) -> list[tuple[str, date]]:
        rows = self._s.execute(text(
            "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
            "JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = 'telemetry_events'")).scalars()
        out = []
        for name in rows:
            m = _PARTITION.match(name)
            if m:
                out.append((name, datetime.strptime(m.group(1), "%Y%m%d").date()))
        return sorted(out, key=lambda x: x[1])

    def retention_days(self) -> int:
        row = self._s.execute(text("SELECT value FROM app_settings WHERE key = :k"), {"k": RETENTION_SETTING}).scalar()
        try:
            return max(1, int((row or {}).get("days", self._default_retention)))
        except (TypeError, ValueError):
            return self._default_retention

    def purge(self, retention_days: int | None = None) -> dict[str, int]:
        """Drop whole partitions older than the retention period (no row-by-row DELETE)."""
        days = retention_days if retention_days is not None else self.retention_days()
        cutoff = (self._clock.now() - timedelta(days=days)).astimezone(timezone.utc)
        dropped = 0
        for name, day in self.list_partitions():
            if day + timedelta(days=1) <= cutoff.date():
                self._s.execute(text(f"DROP TABLE {name}"))
                with _PREPARED_LOCK:
                    _PREPARED_DAYS.discard(day)
                dropped += 1
        removed = self._s.execute(text("DELETE FROM telemetry_events_default WHERE ts < :c"), {"c": cutoff}).rowcount
        return {"partitions_dropped": dropped, "default_rows_removed": removed or 0}

    # -- zones --------------------------------------------------------------------------------------
    def _zone_shapes(self) -> list[air.ZoneShape]:
        rows = self._s.execute(select(Zone)).scalars().all()
        return [air.ZoneShape(z.code, z.criticality, tuple((float(p[0]), float(p[1])) for p in z.polygon))
                for z in rows if z.polygon]

    # -- ingestion ----------------------------------------------------------------------------------
    def ingest(self, identity: DeviceIdentity, events: list[dict[str, Any]]) -> IngestResult:
        """Validate, classify and store events. Every event belongs to the authenticated device's asset."""
        self.ensure_current()
        now = self._clock.now()
        config = self._airspace.get()
        zones = self._zone_shapes()
        rows: list[dict[str, Any]] = []
        messages: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []

        for index, ev in enumerate(events[:MAX_BATCH]):
            problems: list[str] = []
            kind = ev.get("kind")
            etype = ev.get("type", "detection")
            if kind not in KIND_SCOPE:
                problems.append("event.kind_invalid")
            elif KIND_SCOPE[kind] not in identity.scopes:
                problems.append("event.scope_missing")  # a device may only report what its key allows
            if etype not in EVENT_TYPES:
                problems.append("event.type_invalid")
            ts = self._parse_ts(ev.get("ts"), now)
            if ts is None:
                problems.append("event.timestamp_invalid")
            x, y = _num(ev.get("x")), _num(ev.get("y"))
            if (x is None) != (y is None):
                problems.append("event.position_incomplete")
            if x is not None and y is not None:
                if not (-POSITION_MARGIN_M <= x <= 1000 + POSITION_MARGIN_M and
                        -POSITION_MARGIN_M <= y <= 700 + POSITION_MARGIN_M):
                    problems.append("event.position_out_of_range")
            elif kind in AIRBORNE_KINDS and etype == "track":
                problems.append("event.position_required")
            altitude, speed = _num(ev.get("altitude")), _num(ev.get("speed"))
            heading, confidence = _num(ev.get("heading")), _num(ev.get("confidence"))
            if altitude is not None and not -50 <= altitude <= 5000:
                problems.append("event.altitude_invalid")
            if speed is not None and not 0 <= speed <= 500:
                problems.append("event.speed_invalid")
            if heading is not None and not 0 <= heading < 360:
                problems.append("event.heading_invalid")
            if confidence is not None and not 0 <= confidence <= 1:
                problems.append("event.confidence_invalid")
            track_id = ev.get("track_id")
            if track_id is not None and (not isinstance(track_id, str) or not _TRACK_ID.match(track_id)):
                problems.append("event.track_id_invalid")
            data = ev.get("data", {})
            if not isinstance(data, dict) or len(json.dumps(data)) > MAX_PAYLOAD_BYTES:
                problems.append("event.data_invalid")
            if problems:
                rejected.append({"index": index, "codes": problems})
                continue

            zone_code, severity, ring = None, "info", None
            if x is not None and y is not None:
                cls = air.classify(x, y, altitude, config, zones)
                zone_code, severity, ring = cls["zone"], cls["severity"], cls["ring"]
            if kind in ("fence", "access", "cyber") and etype == "alarm":
                severity = "warning" if severity == "info" else severity
            requested = ev.get("severity")
            if requested in air.SEVERITIES and air.SEVERITIES.index(requested) > air.SEVERITIES.index(severity):
                severity = requested  # a sensor may raise, never lower, the server's assessment
            rows.append({
                "ts": ts, "received_at": now, "asset_id": identity.asset_id, "kind": kind, "event_type": etype,
                "track_id": track_id, "x": x, "y": y, "altitude": altitude, "speed": speed, "heading": heading,
                "confidence": confidence, "zone_code": zone_code, "severity": severity,
                "payload": json.dumps(data, sort_keys=True),
            })
            messages.append({
                "asset": identity.asset_code, "kind": kind, "type": etype, "track_id": track_id, "x": x, "y": y,
                "altitude": altitude, "speed": speed, "heading": heading, "confidence": confidence,
                "zone": zone_code, "ring": ring, "severity": severity, "ts": ts.isoformat(),
            })
        if len(events) > MAX_BATCH:
            rejected.append({"index": MAX_BATCH, "codes": ["event.batch_too_large"]})

        if rows:
            self._s.execute(text(
                "INSERT INTO telemetry_events (ts, received_at, asset_id, kind, event_type, track_id, x, y, "
                "altitude, speed, heading, confidence, zone_code, severity, payload) VALUES "
                "(:ts, :received_at, :asset_id, :kind, :event_type, :track_id, :x, :y, :altitude, :speed, "
                ":heading, :confidence, :zone_code, :severity, CAST(:payload AS JSONB))"), rows)
        return IngestResult(accepted=len(rows), rejected=rejected, messages=messages)

    @staticmethod
    def _parse_ts(value: Any, now: datetime) -> datetime | None:
        if value is None:
            return now
        try:
            ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        if ts.tzinfo is None:
            return None
        if ts < now - MAX_AGE or ts > now + MAX_FUTURE:
            return None
        return ts

    # -- reading ------------------------------------------------------------------------------------
    def state(self) -> dict[str, Any]:
        """What the map needs on load: live tracks, threatened zones, sensor status, recent alarms."""
        now = self._clock.now()
        config = self._airspace.get()
        # latest position per track; within 5 s of the newest report a precise source wins over a coarse one
        track_rows = self._s.execute(text(
            "WITH latest AS (SELECT track_id, max(ts) AS last_ts FROM telemetry_events "
            "WHERE ts >= :since AND track_id IS NOT NULL AND x IS NOT NULL GROUP BY track_id) "
            "SELECT DISTINCT ON (e.track_id) e.track_id, e.ts, e.x, e.y, e.altitude, e.speed, e.heading, "
            "e.confidence, e.zone_code, e.severity, e.kind, e.asset_id FROM telemetry_events e "
            "JOIN latest l ON l.track_id = e.track_id AND e.ts >= l.last_ts - interval '5 seconds' "
            "WHERE e.ts >= :since AND e.x IS NOT NULL "
            "ORDER BY e.track_id, (e.kind IN ('radar','eoir')) DESC, e.ts DESC"),
            {"since": now - timedelta(minutes=5)}).mappings().all()
        codes = dict(self._s.execute(select(Asset.id, Asset.code)).all())
        zones = self._zone_shapes()
        tracks = []
        for r in track_rows:
            cls = air.classify(r["x"], r["y"], r["altitude"], config, zones)
            tracks.append({
                "track_id": r["track_id"], "ts": r["ts"].isoformat(), "x": r["x"], "y": r["y"],
                "altitude": r["altitude"], "speed": r["speed"], "heading": r["heading"],
                "confidence": r["confidence"], "zone": r["zone_code"], "ring": cls["ring"],
                "severity": r["severity"], "kind": r["kind"], "asset": codes.get(r["asset_id"], ""),
                "active": now - r["ts"] <= ACTIVE_TRACK_WINDOW, "above_ceiling": cls["above_ceiling"],
            })
        order = {"info": 0, "warning": 1, "critical": 2}
        background = air.background_zone_codes(zones)
        threatened: dict[str, str] = {}
        for t in tracks:
            if t["active"] and t["zone"] and t["zone"] not in background:
                current = threatened.get(t["zone"], "info")
                if order[t["severity"]] >= order[current]:
                    threatened[t["zone"]] = t["severity"]
        sensors = []
        for a in self._s.execute(
            select(Asset).where(Asset.asset_type == "sensor", Asset.status != "decommissioned")
        ).scalars().unique():
            sensors.append({
                "code": a.code, "name": a.name, "x": a.x, "y": a.y, "zone": a.zone.code if a.zone else None,
                "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
                "online": bool(a.last_seen_at and now - a.last_seen_at <= ONLINE_WINDOW),
            })
        alarms = self._s.execute(text(
            "SELECT ts, asset_id, kind, event_type, track_id, zone_code, severity FROM telemetry_events "
            "WHERE ts >= :since AND event_type = 'alarm' "
            "ORDER BY ts DESC LIMIT 50"), {"since": now - timedelta(minutes=15)}).mappings().all()
        return {
            "server_time": now.isoformat(), "airspace": config.to_dict(), "tracks": tracks,
            "threatened_zones": [{"zone": z, "severity": s} for z, s in sorted(threatened.items())],
            "sensors": sensors,
            "alarms": [{"ts": r["ts"].isoformat(), "asset": codes.get(r["asset_id"], ""), "kind": r["kind"],
                        "type": r["event_type"], "track_id": r["track_id"], "zone": r["zone_code"],
                        "severity": r["severity"]} for r in alarms],
        }

    def cyber_alarms(self, since: datetime) -> list[dict[str, Any]]:
        """Cyber alarms reported by sensors or gateways. The target is the asset named in the event data
        (or the reporting device when none is named)."""
        rows = self._s.execute(text(
            "SELECT t.ts, t.severity, a.code AS reporter, "
            "coalesce(t.payload->>'asset', a.code) AS target, t.payload->>'source' AS source, "
            "t.payload->>'summary' AS summary FROM telemetry_events t JOIN assets a ON a.id = t.asset_id "
            "WHERE t.ts >= :since AND t.kind = 'cyber' AND t.event_type = 'alarm' ORDER BY t.ts"),
            {"since": since}).mappings().all()
        return [{"ts": r["ts"].isoformat(), "severity": r["severity"], "asset": r["reporter"], "target": r["target"],
                 "source": r["source"], "summary": r["summary"]} for r in rows]

    def track_history(self, track_id: str, minutes: int = 30, limit: int = 2000) -> list[dict[str, Any]]:
        rows = self._s.execute(text(
            "SELECT ts, x, y, altitude, speed, heading, zone_code, severity, kind FROM telemetry_events "
            "WHERE track_id = :t AND ts >= :since AND x IS NOT NULL ORDER BY ts LIMIT :n"),
            {"t": track_id, "since": self._clock.now() - timedelta(minutes=minutes), "n": limit}).mappings().all()
        if any(r["kind"] in PRECISE_KINDS for r in rows):
            rows = [r for r in rows if r["kind"] in PRECISE_KINDS]  # a clean trail, not a scatter of fixes
        return [{"ts": r["ts"].isoformat(), "x": r["x"], "y": r["y"], "altitude": r["altitude"],
                 "speed": r["speed"], "heading": r["heading"], "zone": r["zone_code"], "severity": r["severity"],
                 "kind": r["kind"]} for r in rows]

    def events(self, *, kind: str = "", severity: str = "", track_id: str = "", minutes: int = 60,
               page: int = 1, page_size: int = 50) -> dict[str, Any]:
        page = max(1, page)
        page_size = min(max(1, page_size), 200)
        where = ["ts >= :since"]
        params: dict[str, Any] = {"since": self._clock.now() - timedelta(minutes=min(max(1, minutes), 24 * 60))}
        if kind:
            where.append("kind = :kind")
            params["kind"] = kind
        if severity:
            where.append("severity = :severity")
            params["severity"] = severity
        if track_id:
            where.append("track_id = :track")
            params["track"] = track_id
        clause = " AND ".join(where)
        total = self._s.execute(text(f"SELECT count(*) FROM telemetry_events WHERE {clause}"), params).scalar_one()
        rows = self._s.execute(text(
            f"SELECT ts, asset_id, kind, event_type, track_id, x, y, altitude, zone_code, severity FROM telemetry_events "
            f"WHERE {clause} ORDER BY ts DESC LIMIT :n OFFSET :o"),
            {**params, "n": page_size, "o": (page - 1) * page_size}).mappings().all()
        codes = dict(self._s.execute(select(Asset.id, Asset.code)).all())
        items = [{"ts": r["ts"].isoformat(), "asset": codes.get(r["asset_id"], ""), "kind": r["kind"],
                  "type": r["event_type"], "track_id": r["track_id"], "x": r["x"], "y": r["y"],
                  "altitude": r["altitude"], "zone": r["zone_code"], "severity": r["severity"]} for r in rows]
        return {"items": items, "total": total, "page": page, "page_size": page_size}
