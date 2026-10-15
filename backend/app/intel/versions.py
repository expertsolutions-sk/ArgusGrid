"""Version comparison and range checks for affected-version specifications."""
from __future__ import annotations

import re
from typing import Any

_SPLIT = re.compile(r"[^0-9A-Za-z]+")


def _key(version: str) -> list[tuple[int, Any]]:
    """Numeric parts compare as numbers and sort before text parts, so 4.2.10 > 4.2.9 and 4.2 < 4.2a."""
    parts = [p for p in _SPLIT.split(version.strip().lower().lstrip("v")) if p]
    return [(0, int(p)) if p.isdigit() else (1, p) for p in parts]


def compare(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    for i in range(max(len(ka), len(kb))):
        pa = ka[i] if i < len(ka) else (0, 0)  # missing parts count as zero: 4.2 == 4.2.0
        pb = kb[i] if i < len(kb) else (0, 0)
        if pa != pb:
            return -1 if pa < pb else 1
    return 0


def in_range(version: str, spec: dict[str, Any] | None) -> bool:
    """True when `version` satisfies the spec. An empty spec means every version is affected.

    spec keys: eq (list of exact versions), gte, gt, lte, lt.
    """
    if not spec:
        return True
    if not version.strip():
        return False  # cannot decide: a version-bound vulnerability does not match an unknown version
    eq = spec.get("eq") or []
    bounded = any(spec.get(k) for k in ("gte", "gt", "lte", "lt"))
    if eq and any(compare(version, v) == 0 for v in eq):
        return True
    if not bounded:
        return not eq  # eq-only spec that did not match
    if spec.get("gte") and compare(version, spec["gte"]) < 0:
        return False
    if spec.get("gt") and compare(version, spec["gt"]) <= 0:
        return False
    if spec.get("lte") and compare(version, spec["lte"]) > 0:
        return False
    if spec.get("lt") and compare(version, spec["lt"]) >= 0:
        return False
    return True
