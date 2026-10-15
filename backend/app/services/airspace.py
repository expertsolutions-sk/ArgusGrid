"""Airspace and zone classification of a position (physical context, ARG-015).

Pure functions plus a small settings-backed service. A position is classified by its distance from the site
centre (alert, warning, critical rings) and by the smallest zone polygon that contains it.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any, Sequence

from app.core.errors import invalid
from app.services.settings_store import SettingsStore

SETTING_KEY = "airspace"
SEVERITIES = ("info", "warning", "critical")
CRITICAL_ZONE_LEVELS = ("critical",)


@dataclass
class AirspaceConfig:
    centre_x: float = 500.0
    centre_y: float = 350.0
    alert_m: float = 1500.0
    warning_m: float = 600.0
    critical_m: float = 150.0
    ceiling_m: float = 120.0  # open-category UAS ceiling in the EU; tracks above are flagged separately

    def to_dict(self) -> dict[str, float]:
        return asdict(self)


@dataclass(frozen=True)
class ZoneShape:
    code: str
    criticality: str
    polygon: tuple[tuple[float, float], ...]

    @property
    def area(self) -> float:
        total = 0.0
        pts = self.polygon
        for i, (x1, y1) in enumerate(pts):
            x2, y2 = pts[(i + 1) % len(pts)]
            total += x1 * y2 - x2 * y1
        return abs(total) / 2


def point_in_polygon(x: float, y: float, polygon: Sequence[Sequence[float]]) -> bool:
    """Ray casting. Points on an edge count as inside."""
    inside = False
    n = len(polygon)
    for i in range(n):
        x1, y1 = polygon[i]
        x2, y2 = polygon[(i + 1) % n]
        if (x1 == x2 == x and min(y1, y2) <= y <= max(y1, y2)) or (y1 == y2 == y and min(x1, x2) <= x <= max(x1, x2)):
            return True
        if (y1 > y) != (y2 > y):
            crossing = (x2 - x1) * (y - y1) / (y2 - y1) + x1
            if x < crossing:
                inside = not inside
    return inside


def zone_at(x: float, y: float, zones: Sequence[ZoneShape]) -> ZoneShape | None:
    """The smallest zone containing the point (so a sector wins over the whole-site fallback zone)."""
    candidates = [z for z in zones if point_in_polygon(x, y, z.polygon)]
    return min(candidates, key=lambda z: z.area) if candidates else None


def background_zone_codes(zones: Sequence[ZoneShape]) -> set[str]:
    """Zones that cover most of the site (the buffer fallback). They locate a position but are never a
    "threatened sector" of their own."""
    if not zones:
        return set()
    largest = max(z.area for z in zones)
    return {z.code for z in zones if len(zones) > 1 and z.area >= 0.8 * largest}


def classify(x: float, y: float, altitude: float | None, config: AirspaceConfig,
             zones: Sequence[ZoneShape]) -> dict[str, Any]:
    """Return the ring, zone and severity of a position."""
    distance = math.hypot(x - config.centre_x, y - config.centre_y)
    if distance <= config.critical_m:
        ring, severity = "critical", "critical"
    elif distance <= config.warning_m:
        ring, severity = "warning", "warning"
    elif distance <= config.alert_m:
        ring, severity = "alert", "info"
    else:
        ring, severity = "outside", "info"
    zone = zone_at(x, y, zones)
    if zone is not None and zone.criticality in CRITICAL_ZONE_LEVELS and ring != "outside":
        severity = "critical"
    above = altitude is not None and altitude > config.ceiling_m
    return {
        "distance_m": round(distance, 1), "ring": ring, "zone": zone.code if zone else None,
        "severity": severity, "above_ceiling": above,
    }


class AirspaceService:
    def __init__(self, store: SettingsStore) -> None:
        self._store = store

    def get(self) -> AirspaceConfig:
        stored = self._store.get(SETTING_KEY) or {}
        base = AirspaceConfig()
        try:
            return AirspaceConfig(**{k: float(stored.get(k, v)) for k, v in base.to_dict().items()})
        except (TypeError, ValueError):
            return base

    def update(self, data: dict[str, Any], actor: str) -> AirspaceConfig:
        try:
            cfg = AirspaceConfig(**{k: float(data[k]) for k in AirspaceConfig().to_dict()})
        except (KeyError, TypeError, ValueError) as exc:
            raise invalid("airspace.invalid_value") from exc
        problems: list[dict[str, Any]] = []
        if not 0 < cfg.critical_m < cfg.warning_m < cfg.alert_m <= 20000:
            problems.append({"code": "airspace.rings_order", "fields": ["critical_m", "warning_m", "alert_m"]})
        if not 0 < cfg.ceiling_m <= 1000:
            problems.append({"code": "airspace.ceiling_invalid", "fields": ["ceiling_m"]})
        if problems:
            raise invalid("airspace.inconsistent", problems)
        self._store.put(SETTING_KEY, cfg.to_dict(), updated_by=actor)
        return cfg
