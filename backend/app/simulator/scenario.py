"""Pure scenario model of the simulator: where the UAV is and what each sensor would report.

No I/O and no clock: everything is a function of simulated seconds, so it is deterministic and testable.
The scenario follows the candidate hooks in docs (plan section 4.10): approach from the north-east, slow
down at the warning ring, loiter within 40 m of the maintenance wireless access point, leave.
All data is fictional.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Waypoint:
    t: float
    x: float
    y: float
    altitude: float


# T+0 radar track at ~1050 m, T+120 s warning ring, T+240 s over the east wall of B2, leaves at T+600 s.
UAV_PATH: tuple[Waypoint, ...] = (
    Waypoint(0, 1450, 800, 90),
    Waypoint(120, 1042, 607, 80),
    Waypoint(240, 470, 322, 30),
    Waypoint(600, 470, 322, 30),
    Waypoint(720, 1000, 760, 70),
    Waypoint(840, 1480, 900, 100),
)
TRACK_ID = "UAV-001"
LOITER_FROM, LOITER_TO = 240.0, 600.0
LOITER_RADIUS_M = 6.0


@dataclass(frozen=True)
class SensorModel:
    code: str
    kind: str
    x: float
    y: float
    range_m: float
    period_s: float
    noise_m: float
    confidence: float
    classifies: bool = False


SENSORS: tuple[SensorModel, ...] = (
    SensorModel("RAD-01", "radar", 425, 335, 1500, 1.0, 8, 0.90),
    SensorModel("RF-01", "rf", 20, 680, 900, 2.0, 30, 0.60),
    SensorModel("RF-02", "rf", 940, 660, 900, 2.0, 30, 0.60),
    SensorModel("RF-03", "rf", 30, 30, 900, 2.0, 30, 0.60),
    SensorModel("RF-04", "rf", 980, 30, 900, 2.0, 30, 0.60),
    SensorModel("EO-01", "eoir", 420, 600, 500, 1.0, 3, 0.95, classifies=True),
    SensorModel("EO-02", "eoir", 800, 240, 450, 1.0, 3, 0.95, classifies=True),
    SensorModel("AC-01", "acoustic", 850, 300, 150, 2.0, 15, 0.50),
)
END_TIME = UAV_PATH[-1].t


def uav_position(t: float) -> tuple[float, float, float, float, float] | None:
    """Return (x, y, altitude, speed m/s, heading degrees) at simulated time t, or None outside the flight."""
    if t < UAV_PATH[0].t or t > UAV_PATH[-1].t:
        return None
    for a, b in zip(UAV_PATH, UAV_PATH[1:]):
        if a.t <= t <= b.t:
            f = (t - a.t) / (b.t - a.t)
            x, y = a.x + (b.x - a.x) * f, a.y + (b.y - a.y) * f
            alt = a.altitude + (b.altitude - a.altitude) * f
            dx, dy, dt = b.x - a.x, b.y - a.y, b.t - a.t
            speed = math.hypot(dx, dy) / dt
            heading = (math.degrees(math.atan2(dx, dy)) + 360) % 360  # compass: 0 = north
            if LOITER_FROM <= t <= LOITER_TO:  # hovering: a slow small circle around the point
                phase = (t - LOITER_FROM) / 20.0
                x += LOITER_RADIUS_M * math.cos(phase)
                y += LOITER_RADIUS_M * math.sin(phase)
                speed = LOITER_RADIUS_M / 20.0
            return x, y, alt, speed, heading
    return None


@dataclass
class SimEvent:
    t: float
    device: str  # asset code of the reporting device
    body: dict[str, Any]


@dataclass
class Scenario:
    """Generates the events due between two simulated instants. Seeded for repeatability."""

    seed: int = 7
    _rng: random.Random = field(init=False)
    _next: dict[str, float] = field(init=False, default_factory=dict)
    _fixed_done: set[str] = field(init=False, default_factory=set)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)
        self._next = {s.code: 0.0 for s in SENSORS}
        self._next["WX-01"] = 0.0

    def events_until(self, t: float) -> list[SimEvent]:
        out: list[SimEvent] = []
        pos = uav_position(t)
        if pos is not None:
            x, y, alt, speed, heading = pos
            for s in SENSORS:
                if t < self._next[s.code]:
                    continue
                self._next[s.code] = t + s.period_s
                if math.hypot(x - s.x, y - s.y) > s.range_m:
                    continue
                body: dict[str, Any] = {
                    "kind": s.kind, "type": "track", "track_id": TRACK_ID,
                    "x": round(x + self._rng.gauss(0, s.noise_m), 1),
                    "y": round(y + self._rng.gauss(0, s.noise_m), 1),
                    "altitude": round(max(0.0, alt + self._rng.gauss(0, 2)), 1),
                    "speed": round(speed, 1), "heading": round(heading, 0),
                    "confidence": s.confidence,
                }
                if s.classifies:
                    body["data"] = {"class": "multirotor", "rotors": 4}
                out.append(SimEvent(t, s.code, body))
        if t >= self._next["WX-01"]:
            self._next["WX-01"] = t + 10.0
            out.append(SimEvent(t, "WX-01", {
                "kind": "weather", "type": "status",
                "data": {"wind_mps": round(3 + self._rng.random() * 2, 1), "visibility_m": 9000},
            }))
        # one-off background and cyber events
        if t >= 60 and "badge" not in self._fixed_done:
            self._fixed_done.add("badge")
            out.append(SimEvent(t, "ACR-B2", {
                "kind": "access", "type": "status", "data": {"door": "B2-main", "event": "badge_ok"}}))
        if t >= 270 and "cyber" not in self._fixed_done:
            self._fixed_done.add("cyber")
            out.append(SimEvent(t, "SENS-GW-01", {
                "kind": "cyber", "type": "alarm", "severity": "warning",
                "data": {"asset": "SCADA-SRV-01", "source": "WIFI-AP-MNT",
                         "summary": "unusual connection to the SCADA server from the maintenance access point"}}))
        return out
