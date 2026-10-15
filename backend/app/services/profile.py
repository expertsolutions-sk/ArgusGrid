"""Dual-use deployment profiles (ARG-021, AG-D-60): `civil` and `defense` change configuration, not code.

The profile is chosen at deployment time (ARGUS_PROFILE) and is not editable at runtime, so a compromised
administrator account cannot turn a defense installation into a civil one.
"""
from __future__ import annotations

from dataclasses import dataclass

PROFILES = ("civil", "defense")
DEFAULT_MARKING = {"civil": "", "defense": "RESTRICTED"}


@dataclass(frozen=True)
class Profile:
    name: str
    marking: str  # banner on every screen and a line in every export; empty = none
    offline_only: bool  # online intelligence sources are never contacted
    telemetry_retention_days: int  # default, an explicit setting still wins
    audit_export_needs_capability: bool = True  # always true; kept explicit for the evidence table

    def public(self) -> dict[str, str]:
        return {"name": self.name, "marking": self.marking}


def build_profile(name: str, marking: str | None = None) -> Profile:
    if name not in PROFILES:
        raise ValueError(f"unknown profile {name!r}")
    text = DEFAULT_MARKING[name] if marking is None else marking.strip()
    if name == "defense":
        return Profile(name, text[:64], offline_only=True, telemetry_retention_days=90)
    return Profile(name, text[:64], offline_only=False, telemetry_retention_days=30)
