"""Hybrid incidents: correlation run, workflow, graph for the operator (ARG-017, ARG-018, ARG-019)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.errors import ApiError, forbidden, invalid, not_found
from app.core.permissions import Cap
from app.correlation import engine as eng
from app.intel import matcher
from app.models.assets import Asset, AssetRelation, Zone
from app.models.identity import RolePermission, User
from app.models.incidents import Incident, IncidentEvent
from app.models.intel import Finding
from app.services import airspace as air
from app.services.audit_service import AuditService, diff
from app.services.intel_service import IntelService
from app.services.mail_service import MailService
from app.services.telemetry_service import TelemetryStore
from app.services.user_service import Viewer

STATUSES = ("new", "triaged", "investigating", "contained", "closed")
SEVERITIES = ("low", "medium", "high", "critical")
TRANSITIONS: dict[str, tuple[str, ...]] = {
    "new": ("triaged", "investigating", "closed"),
    "triaged": ("investigating", "contained", "closed"),
    "investigating": ("contained", "closed"),
    "contained": ("investigating", "closed"),
    "closed": (),
}
WINDOW = timedelta(minutes=15)  # how long a cyber signal and a track count as belonging together
REOPEN_GUARD = timedelta(minutes=30)
MIN_RUN_INTERVAL_S = 1.0
_last_run: dict[str, float] = {}
_run_lock = Lock()


@dataclass
class RunReport:
    created: list[Incident] = field(default_factory=list)
    updated: list[Incident] = field(default_factory=list)
    skipped: bool = False



EVIDENCE_REFRESH_SECONDS = 15  # how often a moving track refreshes the stored evidence

class IncidentService:
    def __init__(self, session: Session, clock: Clock, audit: AuditService, mail: MailService,
                 telemetry: TelemetryStore, intel: IntelService) -> None:
        self._s = session
        self._clock = clock
        self._audit = audit
        self._mail = mail
        self._telemetry = telemetry
        self._intel = intel

    # -- data loading -------------------------------------------------------------------------------
    def _graph(self) -> tuple[dict[int, eng.Node], list[eng.Edge]]:
        nodes = {
            a.id: eng.Node(a.id, a.code, a.name, a.asset_type, a.purdue_level, a.zone.code if a.zone else None,
                           a.criticality, a.x, a.y, tuple(a.exposure or []))
            for a in self._s.execute(select(Asset).where(Asset.status != "decommissioned")).scalars().unique()
        }
        edges = [eng.Edge(r.source_id, r.target_id, r.relation) for r in self._s.execute(select(AssetRelation)).scalars()
                 if r.source_id in nodes and r.target_id in nodes]
        return nodes, edges

    def _signals(self, nodes: dict[int, eng.Node], now: datetime) -> dict[int, list[eng.Signal]]:
        """Cyber signals per asset: alarms of kind `cyber` in the window and exploited open findings."""
        out: dict[int, list[eng.Signal]] = {}
        by_code = {n.code: n for n in nodes.values()}
        for row in self._telemetry.cyber_alarms(now - WINDOW):
            target = by_code.get(str(row["target"]))
            if target is None:
                continue
            strength = {"critical": 0.9, "warning": 0.6}.get(row["severity"], 0.4)
            out.setdefault(target.id, []).append(eng.Signal(
                target.id, "alarm", f"alarm:{row['ts']}", str(row["summary"] or "cyber alarm"), strength,
                {"ts": row["ts"], "source": row["source"], "reported_by": row["asset"]}))
        policy = self._intel.policy()
        for f in self._s.execute(select(Finding).where(Finding.status == "open")).scalars().unique():
            if f.asset_id not in nodes:
                continue
            v = f.vulnerability
            zero_day, zero_hour = self._intel.classification(v, policy)
            if not matcher.exploited(v.kev, v.epss, policy.epss_threshold):
                continue
            strength = 1.0 if zero_day else 0.9 if zero_hour else 0.7
            out.setdefault(f.asset_id, []).append(eng.Signal(
                f.asset_id, "finding", f"finding:{f.id}", v.title or v.vuln_id, strength,
                {"vuln_id": v.vuln_id, "severity": v.severity, "fix_status": v.fix_status,
                 "classification": matcher.label(zero_day, zero_hour), "confidence": f.confidence}))
        return out

    # -- correlation run ----------------------------------------------------------------------------
    def run(self, *, force: bool = False) -> RunReport:
        """Evaluate current tracks and signals and create or update incidents. Cheap; rate limited."""
        report = RunReport()
        marker = f"{id(self._s.bind)}"
        with _run_lock:
            last = _last_run.get(marker, 0.0)
            if not force and time.monotonic() - last < MIN_RUN_INTERVAL_S:
                report.skipped = True
                return report
            _last_run[marker] = time.monotonic()

        now = self._clock.now()
        nodes, edges = self._graph()
        by_id = nodes
        state = self._telemetry.state()
        zones = {z.code: z for z in self._s.execute(select(Zone)).scalars()}
        shapes = [air.ZoneShape(z.code, z.criticality, tuple((float(p[0]), float(p[1])) for p in z.polygon))
                  for z in zones.values() if z.polygon]
        background = air.background_zone_codes(shapes)
        tracks = [eng.Track(t["track_id"], t["x"], t["y"], t["altitude"], t["zone"], t["ring"], t["severity"], t["ts"])
                  for t in state["tracks"]
                  if now - datetime.fromisoformat(t["ts"]) <= WINDOW]
        signals = self._signals(nodes, now)
        radii = {**eng.EXPOSURE_RADIUS_M}

        candidates: dict[str, dict[str, Any]] = {}
        hybrid_assets: set[int] = set()
        for track in tracks:
            options: list[dict[str, Any]] = []
            for asset_id, sigs in signals.items():
                target = nodes[asset_id]
                link = eng.physical_link(track, target, nodes, edges, background, radii)
                if link is None:
                    continue
                hybrid_assets.add(asset_id)
                options.append({"type": "hybrid", "track": track, "target": target, "link": link, "signals": sigs,
                                "zone": target.zone or track.zone, "score": eng.score_hybrid(link, sigs, target)})
            if options:
                # one incident per track: the best-scoring asset is the primary one, the others are listed
                options.sort(key=lambda o: (-o["score"], o["target"].code))
                best = options[0]
                best["others"] = [{"asset": o["target"].code, "score": o["score"],
                                   "signals": len(o["signals"])} for o in options[1:]]
                candidates[f"hybrid|{track.track_id}"] = best
            zone_obj = zones.get(track.zone) if track.zone else None
            if (zone_obj is not None and track.zone not in background and zone_obj.criticality == "critical"
                    and track.severity == "critical"):
                key = f"physical|{track.zone}|{track.track_id}"
                candidates[key] = {"type": "physical", "track": track, "target": None, "link": None, "signals": [],
                                   "zone": track.zone, "score": eng.score_physical(track, zone_obj.criticality)}
        for asset_id, sigs in signals.items():
            alarms = [s for s in sigs if s.kind == "alarm"]
            if alarms and asset_id not in hybrid_assets:
                target = nodes[asset_id]
                key = f"cyber|{target.zone}||{target.code}"
                candidates[key] = {"type": "cyber", "track": None, "target": target, "link": None, "signals": sigs,
                                   "zone": target.zone, "score": eng.score_cyber(sigs, target)}

        # a hybrid incident supersedes the physical-only incident of the same track and zone
        for key in [k for k, c in candidates.items() if c["type"] == "physical"]:
            c = candidates[key]
            if any(o["type"] == "hybrid" and o["track"].track_id == c["track"].track_id for o in candidates.values()):
                del candidates[key]

        for key, c in candidates.items():
            self._upsert(key, c, nodes, edges, now, report, by_id)
        self._s.flush()
        for inc in report.created:
            inc.code = f"{ {'hybrid': 'HYB', 'physical': 'PHY', 'cyber': 'CYB'}[inc.type] }-{inc.id:04d}"
            self._notify(inc)
        return report

    def _upsert(self, key: str, c: dict[str, Any], nodes: dict[int, eng.Node], edges: list[eng.Edge], now: datetime,
                report: RunReport, by_id: dict[int, eng.Node]) -> None:
        target: eng.Node | None = c["target"]
        link: eng.Link | None = c["link"]
        track: eng.Track | None = c["track"]
        radius = eng.blast_radius(target.id, nodes, edges) if target is not None else []
        link_node = nodes.get(link.exposure_asset) if link and link.exposure_asset else None
        remote = sorted({nodes[e.source].code for e in edges if target is not None and e.target == target.id
                         and e.relation == "remote_access" and e.source in nodes})
        severity = eng.severity_from_score(c["score"])
        recs = eng.recommendations(incident_type=c["type"], severity=severity, zone=c["zone"], target=target,
                                   link=link, link_node=link_node, signals=c["signals"], radius=radius,
                                   remote_access_sources=remote, nodes_by_id=nodes)
        evidence = self._evidence(track, link, link_node, c["signals"], nodes)
        if c.get("others"):
            evidence["other_assets"] = c["others"]
        title = self._title(c, link_node)

        existing = self._s.execute(
            select(Incident).where(Incident.key == key).order_by(Incident.id.desc()).limit(1)).scalar_one_or_none()
        if existing is not None and existing.status == "closed":
            if existing.closed_at and now - existing.closed_at < REOPEN_GUARD:
                return
            existing = None
        if existing is None:
            inc = Incident(
                key=key, code="", type=c["type"], severity=severity, score=c["score"], status="new", title=title,
                zone_code=c["zone"], track_id=track.track_id if track else None,
                primary_asset_id=target.id if target else None, link_asset_id=link.exposure_asset if link else None,
                evidence=evidence, blast_radius=radius, recommendations=recs, created_at=now, updated_at=now,
                last_signal_at=now)
            inc.events.append(IncidentEvent(ts=now, kind="created", actor="system", text=title,
                                            details={"score": c["score"], "severity": severity, "rule": c["type"]}))
            self._s.add(inc)
            report.created.append(inc)
            return
        new_primary = target.id if target else None
        if existing.primary_asset_id != new_primary:
            existing.primary_asset_id = new_primary
            existing.link_asset_id = link.exposure_asset if link else None
            existing.zone_code = c["zone"]
        changed_severity = existing.severity != severity
        material = (changed_severity or abs(existing.score - c["score"]) >= 5
                    or self._signature(existing.evidence) != self._signature(evidence))
        existing.last_signal_at = now
        # the track moves every second: keep the position fresh without writing a timeline entry each time
        stale = (now - existing.updated_at).total_seconds() >= EVIDENCE_REFRESH_SECONDS
        if material or stale:
            old = {"severity": existing.severity, "score": existing.score}
            existing.severity, existing.score = severity, c["score"]
            existing.evidence, existing.blast_radius, existing.recommendations = evidence, radius, recs
            existing.title, existing.updated_at = title, now
        if material:
            existing.events.append(IncidentEvent(ts=now, kind="update", actor="system", text="Evidence updated",
                                                 details={"before": old, "score": c["score"], "severity": severity}))
            report.updated.append(existing)

    @staticmethod
    def _signature(evidence: dict[str, Any] | None) -> tuple[Any, ...]:
        """What an operator would call a change: the exposed assets, the signals and the ring, not the position."""
        evidence = evidence or {}
        physical = evidence.get("physical") or {}
        link = physical.get("link") or {}
        cyber = evidence.get("cyber") or {}
        return (
            (physical.get("track") or {}).get("ring"), (physical.get("track") or {}).get("zone"), link.get("kind"),
            link.get("exposed_asset"), tuple(sorted(c["asset"] for c in link.get("candidates") or [])),
            tuple(sorted(a.get("summary") or "" for a in cyber.get("alarms") or [])),
            tuple(sorted(f.get("vuln_id") or "" for f in cyber.get("findings") or [])),
            tuple(sorted(o["asset"] for o in evidence.get("other_assets") or [])),
        )

    @staticmethod
    def _evidence(track: eng.Track | None, link: eng.Link | None, link_node: eng.Node | None,
                  signals: list[eng.Signal], nodes: dict[int, eng.Node]) -> dict[str, Any]:
        evidence: dict[str, Any] = {"physical": None, "cyber": {"alarms": [], "findings": []}}
        if track is not None:
            evidence["physical"] = {
                "track": {"id": track.track_id, "x": track.x, "y": track.y, "altitude": track.altitude,
                          "zone": track.zone, "ring": track.ring, "severity": track.severity, "ts": track.ts},
                "link": None,
            }
            if link is not None:
                evidence["physical"]["link"] = {
                    "kind": link.kind, "exposure": link.exposure, "distance_m": link.distance_m,
                    "radius_m": link.radius_m, "strength": link.strength,
                    "exposed_asset": link_node.code if link_node else None,
                    "path": [nodes[p].code for p in link.path if p in nodes],
                    "candidates": [{"asset": nodes[a].code, "exposure": e, "distance_m": d}
                                   for a, e, d in link.candidates if a in nodes],
                }
        for s in signals:
            if s.kind == "alarm":
                evidence["cyber"]["alarms"].append({"summary": s.title, "source": s.detail.get("source"),
                                                    "reported_by": s.detail.get("reported_by"),
                                                    "ts": s.detail.get("ts")})
            else:
                evidence["cyber"]["findings"].append({
                    "vuln_id": s.detail.get("vuln_id"), "title": s.title, "classification": s.detail.get("classification"),
                    "severity": s.detail.get("severity"), "fix_status": s.detail.get("fix_status")})
        return evidence

    @staticmethod
    def _title(c: dict[str, Any], link_node: eng.Node | None) -> str:
        target: eng.Node | None = c["target"]
        track: eng.Track | None = c["track"]
        if c["type"] == "hybrid" and target and track:
            via = f" near {link_node.code}" if link_node else ""
            return f"UAV {track.track_id}{via} while {target.code} shows a cyber signal"
        if c["type"] == "physical" and track:
            return f"UAV {track.track_id} over the critical zone {c['zone']}"
        return f"Cyber alarm on {target.code}" if target else "Incident"

    # -- notification -------------------------------------------------------------------------------
    def _recipients(self) -> list[User]:
        role_ids = [r for (r,) in self._s.execute(
            select(RolePermission.role_id).where(RolePermission.permission == Cap.INCIDENT_TRIAGE)).all()]
        if not role_ids:
            return []
        return list(self._s.execute(select(User).where(
            User.role_id.in_(role_ids), User.is_active.is_(True), User.email != "", User.is_service.is_(False))).scalars())

    def _notify(self, inc: Incident) -> None:
        if inc.notified_at is not None or SEVERITIES.index(inc.severity) < SEVERITIES.index("high"):
            return
        now = self._clock.now()
        variables = {"incident_id": inc.code, "severity": inc.severity, "zone": inc.zone_code or "-",
                     "summary": inc.title, "detected_at": now.strftime("%Y-%m-%d %H:%M UTC")}
        for user in self._recipients():
            self._mail.queue("incident.hybrid", user, variables)
        inc.notified_at = now
        inc.events.append(IncidentEvent(ts=now, kind="notified", actor="system", text="Alert e-mail queued"))

    # -- views --------------------------------------------------------------------------------------
    def _codes(self) -> dict[int, str]:
        return dict(self._s.execute(select(Asset.id, Asset.code)).all())

    def dto(self, inc: Incident, *, detail: bool = False, codes: dict[int, str] | None = None) -> dict[str, Any]:
        codes = codes or self._codes()
        data: dict[str, Any] = {
            "id": inc.id, "code": inc.code, "type": inc.type, "severity": inc.severity, "score": inc.score,
            "status": inc.status, "escalated": inc.escalated, "title": inc.title, "zone": inc.zone_code,
            "track_id": inc.track_id, "primary_asset": codes.get(inc.primary_asset_id or -1),
            "link_asset": codes.get(inc.link_asset_id or -1), "assigned_to": inc.assigned_to,
            "created_at": inc.created_at.isoformat(), "updated_at": inc.updated_at.isoformat(),
            "last_signal_at": inc.last_signal_at.isoformat(),
            "closed_at": inc.closed_at.isoformat() if inc.closed_at else None,
            "blast_count": len(inc.blast_radius or []),
        }
        if detail:
            data.update({
                "evidence": inc.evidence, "blast_radius": inc.blast_radius, "recommendations": inc.recommendations,
                "transitions": list(TRANSITIONS[inc.status]),
                "timeline": [{"ts": e.ts.isoformat(), "kind": e.kind, "actor": e.actor, "text": e.text,
                              "details": e.details} for e in inc.events],
            })
        return data

    @staticmethod
    def _need(viewer: Viewer, capability: str) -> None:
        if not viewer.has(capability):
            raise forbidden()

    def list(self, viewer: Viewer, *, status: str = "", severity: str = "", type_: str = "", active_only: bool = False,
             page: int = 1, page_size: int = 20) -> dict[str, Any]:
        self._need(viewer, Cap.INCIDENT_VIEW)
        page, page_size = max(1, page), min(max(1, page_size), 200)
        stmt = select(Incident)
        if status:
            stmt = stmt.where(Incident.status == status)
        if active_only:
            stmt = stmt.where(Incident.status != "closed")
        if severity:
            stmt = stmt.where(Incident.severity == severity)
        if type_:
            stmt = stmt.where(Incident.type == type_)
        rows = self._s.execute(stmt).scalars().unique().all()
        rank = {s: i for i, s in enumerate(reversed(SEVERITIES))}
        rows.sort(key=lambda i: (i.status == "closed", rank[i.severity], -i.score, -i.id))
        codes = self._codes()
        total = len(rows)
        items = [self.dto(i, codes=codes) for i in rows[(page - 1) * page_size: page * page_size]]
        return {"items": items, "total": total, "page": page, "page_size": page_size}

    def get(self, viewer: Viewer, incident_id: int) -> dict[str, Any]:
        self._need(viewer, Cap.INCIDENT_VIEW)
        return self.dto(self._load(incident_id), detail=True)

    def _load(self, incident_id: int) -> Incident:
        inc = self._s.get(Incident, incident_id)
        if inc is None:
            raise not_found("incident.not_found")
        return inc

    # -- workflow -----------------------------------------------------------------------------------
    def set_status(self, viewer: Viewer, incident_id: int, status: str, note: str) -> dict[str, Any]:
        inc = self._load(incident_id)
        if status not in STATUSES:
            raise invalid("incident.invalid", [{"code": "incident.status_invalid", "fields": ["status"]}])
        self._need(viewer, Cap.INCIDENT_CLOSE if status == "closed" else Cap.INCIDENT_TRIAGE)
        if status not in TRANSITIONS[inc.status]:
            raise ApiError(409, "incident.transition_not_allowed")
        if len(note) > 500:
            raise invalid("incident.invalid", [{"code": "incident.note_too_long", "fields": ["note"]}])
        before = {"status": inc.status}
        now = self._clock.now()
        inc.status, inc.updated_at = status, now
        if status == "closed":
            inc.closed_at = now
        if status in ("triaged", "investigating") and not inc.assigned_to:
            inc.assigned_to = viewer.ctx.actor.name or ""
        inc.events.append(IncidentEvent(ts=now, kind="status", actor=viewer.ctx.actor.name or "system",
                                        text=note or f"Status: {status}", details={"from": before["status"], "to": status}))
        self._audit.record("incident.status", viewer.ctx, object_type="incident", object_id=inc.id,
                           changes=diff(before, {"status": status}), reason=note[:255],
                           details={"code": inc.code})
        return self.dto(inc, detail=True)

    def escalate(self, viewer: Viewer, incident_id: int, note: str) -> dict[str, Any]:
        self._need(viewer, Cap.INCIDENT_ESCALATE)
        inc = self._load(incident_id)
        if inc.status == "closed":
            raise ApiError(409, "incident.closed")
        now = self._clock.now()
        before = {"severity": inc.severity, "escalated": inc.escalated}
        inc.escalated = True
        if inc.severity != "critical":
            inc.severity = SEVERITIES[SEVERITIES.index(inc.severity) + 1]
        inc.updated_at = now
        inc.events.append(IncidentEvent(ts=now, kind="escalated", actor=viewer.ctx.actor.name or "system",
                                        text=note or "Escalated", details={"severity": inc.severity}))
        self._audit.record("incident.escalate", viewer.ctx, object_type="incident", object_id=inc.id,
                           changes=diff(before, {"severity": inc.severity, "escalated": True}), reason=note[:255],
                           details={"code": inc.code})
        # escalation always alerts the managers that can close incidents
        role_ids = [r for (r,) in self._s.execute(
            select(RolePermission.role_id).where(RolePermission.permission == Cap.INCIDENT_CLOSE)).all()]
        users = self._s.execute(select(User).where(User.role_id.in_(role_ids), User.is_active.is_(True),
                                                   User.email != "")).scalars().all() if role_ids else []
        variables = {"incident_id": inc.code, "severity": inc.severity, "zone": inc.zone_code or "-",
                     "summary": f"ESCALATED: {inc.title}", "detected_at": now.strftime("%Y-%m-%d %H:%M UTC")}
        for u in users:
            self._mail.queue("incident.hybrid", u, variables)
        return self.dto(inc, detail=True)

    def add_note(self, viewer: Viewer, incident_id: int, text_: str) -> dict[str, Any]:
        self._need(viewer, Cap.INCIDENT_TRIAGE)
        inc = self._load(incident_id)
        text_ = text_.strip()
        if not text_ or len(text_) > 1000:
            raise invalid("incident.invalid", [{"code": "incident.note_invalid", "fields": ["text"]}])
        inc.events.append(IncidentEvent(ts=self._clock.now(), kind="note", actor=viewer.ctx.actor.name or "system",
                                        text=text_))
        self._audit.record("incident.note", viewer.ctx, object_type="incident", object_id=inc.id,
                           details={"code": inc.code})
        return self.dto(inc, detail=True)

    # -- graph for the cyber pane -------------------------------------------------------------------
    def graph(self, viewer: Viewer, incident_id: int) -> dict[str, Any]:
        """Nodes and edges of one incident: the physical event, the exposed asset, the compromised asset and
        the assets at risk by hop distance, with the dependency edges among them."""
        self._need(viewer, Cap.INCIDENT_VIEW)
        inc = self._load(incident_id)
        nodes, edges = self._graph()
        roles: dict[int, dict[str, Any]] = {}
        if inc.primary_asset_id in nodes:
            roles[inc.primary_asset_id] = {"role": "compromised", "hop": 0}
        for r in inc.blast_radius or []:
            roles.setdefault(r["asset_id"], {"role": "at_risk", "hop": r["hop"], "impact": r["impact"]})
        link = (inc.evidence or {}).get("physical", {}) or {}
        code_to_id = {n.code: n.id for n in nodes.values()}
        entry_ids = [code_to_id[c["asset"]] for c in ((link.get("link") or {}).get("candidates") or [])
                     if c["asset"] in code_to_id]
        if inc.link_asset_id in nodes and inc.link_asset_id not in entry_ids:
            entry_ids.insert(0, inc.link_asset_id)
        for entry in entry_ids:
            roles.setdefault(entry, {"role": "entry", "hop": -1})
        for code in ((link.get("link") or {}).get("path") or []):
            for n in nodes.values():
                if n.code == code and n.id not in roles:
                    roles[n.id] = {"role": "path", "hop": -1}
        out_nodes = []
        for node_id, info in roles.items():
            n = nodes[node_id]
            out_nodes.append({"id": f"a{n.id}", "asset_id": n.id, "code": n.code, "name": n.name,
                              "asset_type": n.asset_type, "level": n.level, "zone": n.zone,
                              "criticality": n.criticality, **info})
        out_edges = [{"id": f"e{e.source}-{e.target}-{e.relation}", "source": f"a{e.source}", "target": f"a{e.target}",
                      "kind": "relation", "relation": e.relation}
                     for e in edges if e.source in roles and e.target in roles]
        if inc.type != "cyber":
            track = (link.get("track") or {})
            out_nodes.append({"id": "event", "asset_id": None, "code": inc.track_id or "UAV", "name": "Physical event",
                              "asset_type": "physical_event", "level": "", "zone": inc.zone_code,
                              "criticality": inc.severity, "role": "physical_event", "hop": -2,
                              "detail": {"altitude": track.get("altitude"), "ring": track.get("ring")}})
            anchors = [e for e in entry_ids if e in roles]
            if not anchors and inc.primary_asset_id in roles:
                anchors = [inc.primary_asset_id]
            for anchor in anchors:
                out_edges.append({"id": f"hybrid-{anchor}", "source": "event", "target": f"a{anchor}",
                                  "kind": "hybrid", "relation": "hybrid"})
        return {"incident": self.dto(inc, detail=True), "nodes": out_nodes, "edges": out_edges}

    def overview(self, viewer: Viewer) -> dict[str, Any]:
        self._need(viewer, Cap.INCIDENT_VIEW)
        rows = self._s.execute(select(Incident).where(Incident.status != "closed")).scalars().unique().all()
        counts = {s: 0 for s in SEVERITIES}
        for i in rows:
            counts[i.severity] += 1
        return {"open": len(rows), "by_severity": counts}

