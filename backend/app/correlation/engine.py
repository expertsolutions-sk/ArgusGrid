"""Correlation of physical tracks and cyber signals into hybrid incidents (ARG-017). Pure functions.

Rule of the prototype (docs/DECISIONS.md AG-D-52): a UAV track is *linked* to an asset with a cyber signal
(an alarm or an exploited finding) when the track is near an asset that can physically be reached from outside
(wireless, line of sight, GNSS, console) and that asset has a dependency path to the asset with the signal,
or when the track is inside the zone of that asset. The result is a score, a blast radius over the
dependency edges and a list of recommended actions (the platform never acts by itself).
"""
from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

CRITICALITY = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
# metres within which a track can physically act on an exposed asset
EXPOSURE_RADIUS_M = {"wireless": 150.0, "gnss": 300.0, "line_of_sight": 300.0, "electromagnetic": 100.0,
                     "physical_access": 40.0}
DOMINO_RELATIONS = ("control", "engineering", "remote_access", "operator_session", "replication", "wireless_link")
IMPACT = {"control": "control", "engineering": "control", "remote_access": "access", "operator_session": "access",
          "replication": "access", "wireless_link": "access", "data_flow": "data"}
IMPACT_WEIGHT = {"control": 1.0, "access": 0.6, "data": 0.3}


@dataclass(frozen=True)
class Node:
    id: int
    code: str
    name: str
    asset_type: str
    level: str
    zone: str | None
    criticality: str
    x: float | None
    y: float | None
    exposure: tuple[str, ...] = ()


@dataclass(frozen=True)
class Edge:
    source: int
    target: int
    relation: str


@dataclass(frozen=True)
class Track:
    track_id: str
    x: float
    y: float
    altitude: float | None
    zone: str | None
    ring: str
    severity: str
    ts: str


@dataclass(frozen=True)
class Signal:
    """A cyber signal on one asset: an alarm from a sensor or gateway, or an exploited finding."""

    asset_id: int
    kind: str  # alarm | finding
    ref: str
    title: str
    strength: float  # 0..1 how exploitable or severe
    detail: dict[str, Any] = field(default_factory=dict, hash=False, compare=False)


@dataclass(frozen=True)
class Link:
    kind: str  # proximity | zone
    exposure_asset: int | None
    exposure: str | None
    distance_m: float
    radius_m: float
    strength: float
    path: tuple[int, ...]  # asset ids from the exposed asset to the target
    # every exposed asset the track is within reach of: (asset id, exposure, distance in metres)
    candidates: tuple[tuple[int, str, float], ...] = ()


# -- graph helpers ------------------------------------------------------------------------------------
def adjacency(edges: Iterable[Edge]) -> tuple[dict[int, list[Edge]], dict[int, list[Edge]]]:
    out: dict[int, list[Edge]] = {}
    inc: dict[int, list[Edge]] = {}
    for e in edges:
        out.setdefault(e.source, []).append(e)
        inc.setdefault(e.target, []).append(e)
    return out, inc


def blast_radius(source: int, nodes: dict[int, Node], edges: Iterable[Edge], max_hops: int = 3) -> list[dict[str, Any]]:
    """Assets reachable from `source` along dependency edges, by hop distance (the domino effect).

    Follows control, engineering, access and replication relations; a data flow is listed only at the first
    hop (information, not control). Each entry keeps the path so an operator can see why it is at risk.
    """
    out, _ = adjacency(edges)
    seen: dict[int, tuple[int, list[int], str]] = {source: (0, [source], "control")}
    queue: deque[int] = deque([source])
    while queue:
        current = queue.popleft()
        hop, path, _impact = seen[current]
        if hop >= max_hops:
            continue
        for e in out.get(current, []):
            if e.target in seen or e.target not in nodes:
                continue
            impact = IMPACT.get(e.relation, "access")
            if e.relation == "data_flow" and hop >= 1:
                continue
            if e.relation not in DOMINO_RELATIONS and e.relation != "data_flow":
                continue
            seen[e.target] = (hop + 1, [*path, e.target], impact)
            if impact != "data":
                queue.append(e.target)
    result = []
    for node_id, (hop, path, impact) in seen.items():
        if node_id == source:
            continue
        n = nodes[node_id]
        consequence = CRITICALITY.get(n.criticality, 0.5) * IMPACT_WEIGHT[impact] / hop
        result.append({
            "asset_id": n.id, "asset": n.code, "name": n.name, "asset_type": n.asset_type, "level": n.level,
            "zone": n.zone, "criticality": n.criticality, "hop": hop, "impact": impact,
            "via": [nodes[p].code for p in path if p in nodes], "consequence": round(consequence, 3),
        })
    result.sort(key=lambda r: (-r["consequence"], r["hop"], r["asset"]))
    return result


def paths_to(target: int, nodes: dict[int, Node], edges: Iterable[Edge], max_hops: int = 3) -> dict[int, tuple[int, ...]]:
    """Assets from which `target` can be reached (reverse search), with the path from that asset to the target."""
    _, inc = adjacency(edges)
    found: dict[int, tuple[int, ...]] = {target: (target,)}
    queue: deque[int] = deque([target])
    while queue:
        current = queue.popleft()
        path = found[current]
        if len(path) - 1 >= max_hops:
            continue
        for e in inc.get(current, []):
            if e.source in found or e.source not in nodes or e.relation not in (*DOMINO_RELATIONS, "data_flow"):
                continue
            found[e.source] = (e.source, *path)
            queue.append(e.source)
    return found


def distance(x1: float, y1: float, x2: float, y2: float) -> float:
    return math.hypot(x1 - x2, y1 - y2)


def physical_link(track: Track, target: Node, nodes: dict[int, Node], edges: list[Edge],
                  background_zones: set[str], radii: dict[str, float] | None = None) -> Link | None:
    """Best physical link between a track and the asset that shows a cyber signal, or None."""
    radii = radii or EXPOSURE_RADIUS_M
    best: Link | None = None
    reach: list[tuple[int, str, float]] = []
    for asset_id, path in paths_to(target.id, nodes, edges).items():
        e = nodes[asset_id]
        if not e.exposure or e.x is None or e.y is None:
            continue
        d = distance(track.x, track.y, e.x, e.y)
        for exposure in e.exposure:
            radius = radii.get(exposure, 0.0)
            if radius > 0 and d <= radius:
                # nearer is stronger; a shorter dependency path is stronger
                strength = (1.0 - d / radius) * (0.5 + 0.5 * (1.0 / max(1, len(path) - 1)) if len(path) > 1 else 1.0)
                strength = max(0.2, min(1.0, 0.4 + 0.6 * strength))
                link = Link("proximity", e.id, exposure, round(d, 1), radius, round(strength, 3), path)
                reach.append((e.id, exposure, round(d, 1)))
                if best is None or link.strength > best.strength:
                    best = link
    if best is not None:
        reach.sort(key=lambda r: r[2])
        best = Link(best.kind, best.exposure_asset, best.exposure, best.distance_m, best.radius_m, best.strength,
                    best.path, tuple(reach))
    if best is None and target.zone and track.zone == target.zone and target.zone not in background_zones:
        d = distance(track.x, track.y, target.x, target.y) if target.x is not None and target.y is not None else 0.0
        best = Link("zone", None, None, round(d, 1), 0.0, 0.4, (target.id,))
    return best


# -- scoring ------------------------------------------------------------------------------------------
def severity_from_score(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def score_hybrid(link: Link, signals: list[Signal], target: Node) -> float:
    exploit = max((s.strength for s in signals), default=0.0)
    both = any(s.kind == "alarm" for s in signals) and any(s.kind == "finding" for s in signals)
    value = 100 * (0.35 * link.strength + 0.35 * exploit + 0.30 * CRITICALITY.get(target.criticality, 0.5))
    return round(min(100.0, value + (10 if both else 0)), 1)


def score_physical(track: Track, zone_criticality: str) -> float:
    ring = {"critical": 1.0, "warning": 0.6, "alert": 0.3}.get(track.ring, 0.1)
    return round(min(85.0, 100 * (0.5 * ring + 0.5 * CRITICALITY.get(zone_criticality, 0.25))), 1)


def score_cyber(signals: list[Signal], target: Node) -> float:
    exploit = max((s.strength for s in signals), default=0.0)
    return round(min(75.0, 100 * (0.6 * exploit + 0.4 * CRITICALITY.get(target.criticality, 0.5))), 1)


# -- recommendations ----------------------------------------------------------------------------------
def recommendations(*, incident_type: str, severity: str, zone: str | None, target: Node | None,
                    link: Link | None, link_node: Node | None, signals: list[Signal],
                    radius: list[dict[str, Any]], remote_access_sources: list[str],
                    nodes_by_id: dict[int, Node] | None = None) -> list[dict[str, Any]]:
    """Codes with parameters; the client renders the wording. Recommendations only, never actions."""
    recs: list[dict[str, Any]] = []
    nodes_by_id = nodes_by_id or ({link_node.id: link_node} if link_node is not None else {})
    if incident_type in ("hybrid", "physical"):
        recs.append({"code": "dispatch_security", "zone": zone})
    if link:
        for asset_id, exposure, _d in link.candidates:
            if exposure == "wireless" and asset_id in nodes_by_id:
                recs.append({"code": "disable_wireless", "asset": nodes_by_id[asset_id].code})
    if link and link.exposure == "gnss" and link_node is not None:
        recs.append({"code": "verify_time_source", "asset": link_node.code})
    if target is not None and incident_type in ("hybrid", "cyber"):
        fixes = {str(s.detail.get("fix_status", "")) for s in signals if s.kind == "finding"}
        recs.append({"code": "isolate_asset", "asset": target.code})
        if "none" in fixes:
            recs.append({"code": "request_vendor_mitigation", "asset": target.code})
        if "available" in fixes:
            recs.append({"code": "apply_vendor_fix", "asset": target.code})
        for source in remote_access_sources:
            recs.append({"code": "restrict_remote_access", "asset": source})
        controllers = [r["asset"] for r in radius if r["asset_type"] in ("plc", "rtu", "ied") and r["impact"] == "control"]
        if controllers:
            recs.append({"code": "verify_controller_integrity", "assets": controllers[:6]})
        recs.append({"code": "review_logs", "asset": target.code})
    if severity in ("critical", "high"):
        recs.append({"code": "notify_management"})
    if severity == "critical":
        recs.append({"code": "notify_dispatcher"})
    return recs
