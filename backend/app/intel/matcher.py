"""Matching of vulnerability records to the software inventory, and classification (ARG-016).

Pure functions. Definitions (docs/DECISIONS.md AG-D-46):
- exploited:  known exploited (KEV) or EPSS at or above the configured threshold.
- zero-day:   exploited and no vendor fix exists.
- zero-hour:  exploited and published (or first seen) within the configured number of hours.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.intel.parsers import parse_cpe
from app.intel.versions import in_range

_NORM = re.compile(r"[^a-z0-9]+")


def norm(text: str) -> str:
    """Lower-case, punctuation to single spaces: 'Voltek_SCADA-Server' == 'voltek scada server'."""
    return _NORM.sub(" ", text.lower()).strip()


@dataclass(frozen=True)
class SoftwareRef:
    name: str
    vendor: str
    version: str
    cpe: str = ""
    basis: str = "product"  # product | firmware


@dataclass(frozen=True)
class Match:
    matched_on: str
    basis: str  # cpe | product | firmware
    confidence: str = "high"  # high: version-bounded or exact; low: product only, the version cannot be checked


def _product_matches(spec_vendor: str, spec_product: str, sw: SoftwareRef) -> bool:
    product = norm(spec_product)
    if not product:
        return False
    name = norm(sw.name)
    if product != name:
        # a product name that is only part of the software name must be long enough to be specific
        if len(product) < 5 or (f" {product} " not in f" {name} "
                                and f" {product} " not in f" {norm(sw.vendor)} {name} "):
            return False
    vendor = norm(spec_vendor)
    if not vendor:
        return True
    return vendor in norm(sw.vendor) or vendor in name or vendor == name.split(" ")[0]


def match_software(affected: list[dict[str, Any]], sw: SoftwareRef) -> Match | None:
    """Return the first affected specification that applies to one software entry."""
    sw_cpe = parse_cpe(sw.cpe) if sw.cpe else {}
    for spec in affected:
        spec_cpe = parse_cpe(spec.get("cpe", "")) if spec.get("cpe") else {}
        basis = ""
        if spec_cpe and sw_cpe:
            if norm(spec_cpe["vendor"]) == norm(sw_cpe["vendor"]) and norm(spec_cpe["product"]) == norm(sw_cpe["product"]):
                basis = "cpe"
        if not basis and _product_matches(str(spec.get("vendor", "")), str(spec.get("product", "")), sw):
            basis = sw.basis if sw.basis == "firmware" else "product"
        if not basis:
            continue
        if in_range(sw.version, spec.get("versions") or {}):
            bounded = bool(spec.get("versions"))
            return Match(matched_on=f"{sw.name} {sw.version}".strip(), basis=basis,
                         confidence="high" if bounded else "low")
    return None


def exploited(kev: bool, epss: float | None, epss_threshold: float) -> bool:
    return bool(kev or (epss is not None and epss >= epss_threshold))


def classify(*, kev: bool, epss: float | None, fix_status: str, published_at: datetime | None,
             first_seen_at: datetime, now: datetime, zero_hour_hours: int,
             epss_threshold: float) -> tuple[bool, bool]:
    """Return (is_zero_day, is_zero_hour)."""
    hot = exploited(kev, epss, epss_threshold)
    zero_day = hot and fix_status == "none"
    reference = published_at or first_seen_at
    zero_hour = hot and now - reference <= timedelta(hours=zero_hour_hours)
    return zero_day, zero_hour


def label(is_zero_day: bool, is_zero_hour: bool) -> str:
    return "zero_day" if is_zero_day else "zero_hour" if is_zero_hour else "ordinary"
