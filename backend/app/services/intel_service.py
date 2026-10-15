"""Vulnerability intelligence: sources, import, matching to the inventory, findings, alerts (ARG-016)."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.errors import ApiError, forbidden, invalid, not_found
from app.core.permissions import Cap
from app.intel import bundle as bundle_mod
from app.intel import matcher
from app.intel.parsers import PARSERS, FeedError
from app.models.assets import Asset
from app.models.identity import RolePermission, User
from app.models.intel import Finding, IntelSource, Vulnerability
from app.services.audit_service import AuditService, diff
from app.services.mail_service import MailService
from app.services.settings_store import SettingsStore
from app.services.user_service import Viewer

POLICY_KEY = "intel_policy"
TRUSTED_KEYS = "intel_trusted_keys"
SEVERITIES = ("low", "medium", "high", "critical")
FIX_STATUSES = ("none", "available", "workaround", "unknown")
FINDING_STATUSES = ("open", "acknowledged", "mitigated", "false_positive")
MAX_IMPORT_BYTES = 25 * 1024 * 1024
MAX_RECORDS = 50_000

DEFAULT_SOURCES = (
    ("kev", "CISA Known Exploited Vulnerabilities", "kev",
     "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 6),
    ("epss", "FIRST EPSS scores", "epss", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", 24),
    ("nvd", "NIST NVD CVE API 2.0", "nvd", "https://services.nvd.nist.gov/rest/json/cves/2.0", 6),
    ("csaf", "CSAF advisories (vendor or CERT)", "csaf", "", 12),
    ("bundle", "Signed offline bundle", "bundle", "", 0),
)


# -- fetching ------------------------------------------------------------------------------------------
class Fetcher(Protocol):
    def get(self, url: str, params: dict[str, str] | None = None) -> bytes: ...


class FetchError(RuntimeError):
    pass


class HttpFetcher:
    """HTTPS only (plain HTTP only to loopback), at most 3 redirects and each target is checked like the
    original URL, size cap, no credentials in the URL."""

    MAX_REDIRECTS = 3

    def __init__(self, timeout: float = 30.0, max_bytes: int = MAX_IMPORT_BYTES) -> None:
        self._timeout = timeout
        self._max = max_bytes

    def get(self, url: str, params: dict[str, str] | None = None) -> bytes:
        from urllib.parse import urljoin

        current, query = url, params
        for _ in range(self.MAX_REDIRECTS + 1):
            check_url(current)
            try:
                with httpx.stream("GET", current, params=query, timeout=self._timeout, follow_redirects=False,
                                  headers={"User-Agent": "ArgusGrid-intel/0.1"}) as response:
                    if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("location"):
                        current, query = urljoin(current, response.headers["location"]), None
                        continue
                    if response.status_code != 200:
                        raise FetchError(f"HTTP {response.status_code}")
                    data = bytearray()
                    for chunk in response.iter_bytes():
                        data.extend(chunk)
                        if len(data) > self._max:
                            raise FetchError("response too large")
                    return bytes(data)
            except httpx.HTTPError as exc:
                raise FetchError(type(exc).__name__) from exc
        raise FetchError("too many redirects")


def check_url(url: str) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.username or parsed.password or not host:
        raise FetchError("url not allowed")
    loopback = host in ("localhost",) or _is_loopback(host)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise FetchError("https required")


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# -- policy --------------------------------------------------------------------------------------------
@dataclass
class IntelPolicy:
    zero_hour_hours: int = 72
    epss_threshold: float = 0.5
    notify_min_severity: str = "high"
    notify: bool = True
    offline_only: bool = False  # defense profile: online sources are never contacted

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MatchReport:
    new_findings: list[Finding] = field(default_factory=list)
    checked_assets: int = 0


@dataclass
class IngestReport:
    created: int = 0
    updated: int = 0
    skipped: int = 0
    new_findings: int = 0
    notified: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)  # for the live stream


class IntelService:
    def __init__(self, session: Session, clock: Clock, store: SettingsStore, audit: AuditService,
                 mail: MailService, offline_forced: bool = False) -> None:
        self._offline_forced = offline_forced  # the defense profile never contacts online sources
        self._s = session
        self._clock = clock
        self._store = store
        self._audit = audit
        self._mail = mail

    # -- policy and trust ---------------------------------------------------------------------------
    def policy(self) -> IntelPolicy:
        stored = self._store.get(POLICY_KEY) or {}
        base = IntelPolicy()
        try:
            return IntelPolicy(
                zero_hour_hours=int(stored.get("zero_hour_hours", base.zero_hour_hours)),
                epss_threshold=float(stored.get("epss_threshold", base.epss_threshold)),
                notify_min_severity=str(stored.get("notify_min_severity", base.notify_min_severity)),
                notify=bool(stored.get("notify", base.notify)),
                offline_only=self._offline_forced or bool(stored.get("offline_only", base.offline_only)),
            )
        except (TypeError, ValueError):
            return replace(base, offline_only=self._offline_forced)

    def update_policy(self, data: dict[str, Any], actor: str) -> IntelPolicy:
        problems: list[dict[str, Any]] = []
        try:
            policy = IntelPolicy(
                zero_hour_hours=int(data["zero_hour_hours"]), epss_threshold=float(data["epss_threshold"]),
                notify_min_severity=str(data["notify_min_severity"]), notify=bool(data["notify"]),
                offline_only=bool(data["offline_only"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise invalid("intel.invalid_value") from exc
        if self._offline_forced and not policy.offline_only:
            problems.append({"code": "intel.profile_offline_forced", "fields": ["offline_only"]})
        if not 1 <= policy.zero_hour_hours <= 24 * 30:
            problems.append({"code": "intel.zero_hour_range", "fields": ["zero_hour_hours"]})
        if not 0.0 <= policy.epss_threshold <= 1.0:
            problems.append({"code": "intel.epss_range", "fields": ["epss_threshold"]})
        if policy.notify_min_severity not in SEVERITIES:
            problems.append({"code": "intel.severity_invalid", "fields": ["notify_min_severity"]})
        if problems:
            raise invalid("intel.inconsistent", problems)
        self._store.put(POLICY_KEY, policy.to_dict(), updated_by=actor)
        return policy

    def trusted_keys(self) -> list[dict[str, str]]:
        return list((self._store.get(TRUSTED_KEYS) or {}).get("keys", []))

    def set_trusted_keys(self, keys: list[dict[str, str]], actor: str) -> list[dict[str, str]]:
        import base64

        clean: list[dict[str, str]] = []
        for k in keys:
            key_id, public, label = str(k.get("key_id", "")).strip(), str(k.get("public_key", "")).strip(), \
                str(k.get("label", ""))[:64]
            try:
                if not key_id or len(key_id) > 64 or len(base64.b64decode(public, validate=True)) != 32:
                    raise ValueError
            except ValueError as exc:
                raise invalid("intel.key_invalid", [{"code": "intel.key_invalid", "fields": ["keys"]}]) from exc
            clean.append({"key_id": key_id, "public_key": public, "label": label})
        self._store.put(TRUSTED_KEYS, {"keys": clean}, updated_by=actor)
        return clean

    # -- sources ------------------------------------------------------------------------------------
    def ensure_sources(self) -> None:
        existing = {s.key for s in self._s.execute(select(IntelSource)).scalars()}
        for key, name, kind, url, hours in DEFAULT_SOURCES:
            if key not in existing:
                self._s.add(IntelSource(key=key, name=name, kind=kind, url=url, interval_hours=hours,
                                        enabled=False, last_status="never"))
        self._s.flush()

    def sources(self) -> list[dict[str, Any]]:
        self.ensure_sources()
        rows = self._s.execute(select(IntelSource).order_by(IntelSource.id)).scalars()
        return [self._source_dto(s) for s in rows]

    @staticmethod
    def _source_dto(s: IntelSource) -> dict[str, Any]:
        return {"key": s.key, "name": s.name, "kind": s.kind, "enabled": s.enabled, "url": s.url,
                "interval_hours": s.interval_hours, "last_status": s.last_status, "last_error": s.last_error,
                "last_items": s.last_items, "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None}

    def update_source(self, viewer: Viewer, key: str, data: dict[str, Any]) -> dict[str, Any]:
        self._need(viewer, Cap.INTEL_SOURCES_MANAGE)
        self.ensure_sources()
        source = self._s.execute(select(IntelSource).where(IntelSource.key == key)).scalar_one_or_none()
        if source is None:
            raise not_found("intel.source_not_found")
        before = self._source_dto(source)
        problems: list[dict[str, Any]] = []
        if "url" in data:
            url = str(data["url"]).strip()
            if url:
                try:
                    check_url(url)
                except FetchError:
                    problems.append({"code": "intel.url_invalid", "fields": ["url"]})
            source.url = url
        if "interval_hours" in data:
            hours = data["interval_hours"]
            if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= 24 * 30:
                problems.append({"code": "intel.interval_invalid", "fields": ["interval_hours"]})
            else:
                source.interval_hours = hours
        if "enabled" in data:
            source.enabled = bool(data["enabled"])
            if source.enabled and (source.kind in ("bundle",) or not source.url):
                problems.append({"code": "intel.source_not_fetchable", "fields": ["enabled", "url"]})
            if source.enabled and self.policy().offline_only:
                problems.append({"code": "intel.offline_only", "fields": ["enabled"]})
        if problems:
            self._s.rollback()
            raise invalid("intel.invalid", problems)
        self._audit.record("intel.source.update", viewer.ctx, object_type="intel_source", object_id=key,
                           changes=diff(before, self._source_dto(source)))
        return self._source_dto(source)

    # -- import -------------------------------------------------------------------------------------
    @staticmethod
    def _need(viewer: Viewer, capability: str) -> None:
        if not viewer.has(capability):
            raise forbidden()

    def import_payload(self, viewer: Viewer | None, fmt: str, payload: Any, *, source_key: str = "manual",
                       is_demo: bool = False) -> IngestReport:
        """Parse a feed document (kev, nvd, epss, csaf), a verified bundle, or already normalised records."""
        if viewer is not None:
            self._need(viewer, Cap.INTEL_SOURCES_MANAGE)
        records = self._records_from(fmt, payload)
        # EPSS only scores what is already known; it must not create a record for every CVE in existence
        report = self._ingest(records, source_key, is_demo=is_demo, create_missing=fmt != "epss")
        if viewer is not None:
            self._audit.record("intel.import", viewer.ctx, object_type="intel", object_id=source_key,
                               details={"format": fmt, "created": report.created, "updated": report.updated,
                                        "skipped": report.skipped, "new_findings": report.new_findings})
        return report

    def _records_from(self, fmt: str, payload: Any) -> list[dict[str, Any]]:
        try:
            if fmt == "bundle":
                trusted = {k["key_id"]: k["public_key"] for k in self.trusted_keys()}
                document = json.loads(payload) if isinstance(payload, str) else payload
                return bundle_mod.verify_bundle(document, trusted)
            if fmt == "records":
                document = json.loads(payload) if isinstance(payload, str) else payload
                if not isinstance(document, list):
                    raise FeedError("records must be a list")
                return document
            parser = PARSERS.get(fmt)
            if parser is None:
                raise invalid("intel.format_unknown")
            return parser(payload)
        except bundle_mod.BundleError as exc:
            raise ApiError(422, "intel.bundle_rejected", [{"code": exc.code, "fields": ["payload"]}]) from exc
        except (FeedError, json.JSONDecodeError) as exc:
            raise ApiError(422, "intel.feed_invalid", [{"code": "intel.feed_invalid", "fields": ["payload"]}]) from exc

    def _ingest(self, records: list[dict[str, Any]], source_key: str, *, is_demo: bool = False,
                create_missing: bool = True) -> IngestReport:
        report = IngestReport()
        now = self._clock.now()
        if len(records) > MAX_RECORDS:
            raise ApiError(422, "intel.too_many_records")
        wanted = [str(r.get("vuln_id", "")).upper() for r in records if r.get("vuln_id")]
        existing: dict[str, Vulnerability] = {}
        for start in range(0, len(wanted), 5000):  # chunked: a feed can hold hundreds of thousands of ids
            chunk = wanted[start:start + 5000]
            for v in self._s.execute(select(Vulnerability).where(Vulnerability.vuln_id.in_(chunk))).scalars():
                existing[v.vuln_id] = v
        for rec in records:
            vid = str(rec.get("vuln_id", "")).strip().upper()
            if not vid or len(vid) > 64:
                report.skipped += 1
                continue
            vuln = existing.get(vid)
            is_new = vuln is None
            if vuln is None and not create_missing:
                report.skipped += 1
                continue
            if vuln is None:
                vuln = Vulnerability(vuln_id=vid, first_seen_at=now, updated_at=now, affected=[], references=[],
                                     sources=[], is_demo=is_demo)
                self._s.add(vuln)
                existing[vid] = vuln
                report.created += 1
            changed = self._apply(vuln, rec, source_key)
            if changed and not is_new:
                vuln.updated_at = now
                report.updated += 1
        self._s.flush()
        match = self.match_all()
        report.new_findings = len(match.new_findings)
        report.notified = self._notify(match.new_findings)
        report.findings = [self.finding_event(f) for f in match.new_findings]
        return report

    @staticmethod
    def _apply(vuln: Vulnerability, rec: dict[str, Any], source_key: str) -> bool:
        """Merge a record into a vulnerability. Keys a source does not provide never erase what is known."""
        changed = False

        def set_if(attr: str, value: Any) -> None:
            nonlocal changed
            if value is not None and getattr(vuln, attr) != value:
                setattr(vuln, attr, value)
                changed = True

        if rec.get("title"):
            set_if("title", str(rec["title"])[:255])
        if rec.get("description"):
            set_if("description", str(rec["description"]))
        if rec.get("severity") in SEVERITIES:
            set_if("severity", rec["severity"])
        if isinstance(rec.get("cvss"), (int, float)):
            set_if("cvss", float(rec["cvss"]))
        if isinstance(rec.get("epss"), (int, float)):
            set_if("epss", float(rec["epss"]))
        if rec.get("kev") is True:
            set_if("kev", True)  # exploitation, once known, is not forgotten by a feed that does not say it
        if rec.get("fix_status") in FIX_STATUSES:
            if not (rec["fix_status"] == "unknown" and vuln.fix_status != "unknown"):
                set_if("fix_status", rec["fix_status"])
        if rec.get("published_at"):
            try:
                set_if("published_at", datetime.fromisoformat(str(rec["published_at"])))
            except ValueError:
                pass
        affected = rec.get("affected")
        if isinstance(affected, list) and affected:
            clean = [{"vendor": str(a.get("vendor", ""))[:96], "product": str(a.get("product", ""))[:128],
                      "cpe": str(a.get("cpe", ""))[:255], "versions": a.get("versions") or {}}
                     for a in affected if isinstance(a, dict)]
            merged = list(vuln.affected or [])
            for a in clean:
                if a not in merged:
                    merged.append(a)
            if merged != vuln.affected:
                vuln.affected = merged
                changed = True
        refs = rec.get("references")
        if isinstance(refs, list):
            merged_refs = list(dict.fromkeys([*(vuln.references or []), *[str(r)[:300] for r in refs]]))[:20]
            if merged_refs != vuln.references:
                vuln.references = merged_refs
                changed = True
        if source_key not in (vuln.sources or []):
            vuln.sources = [*(vuln.sources or []), source_key]
            changed = True
        return changed

    # -- matching -----------------------------------------------------------------------------------
    def _software_refs(self, asset: Asset) -> list[matcher.SoftwareRef]:
        refs = [matcher.SoftwareRef(name=s.name, vendor=s.vendor, version=s.version, cpe=s.cpe)
                for s in asset.software]
        if asset.model and asset.firmware_version:
            refs.append(matcher.SoftwareRef(name=asset.model, vendor=asset.vendor, version=asset.firmware_version,
                                            basis="firmware"))
        return refs

    def match_all(self) -> MatchReport:
        return self._match(self._s.execute(
            select(Asset).where(Asset.status != "decommissioned")).scalars().unique().all())

    def match_asset(self, asset: Asset) -> MatchReport:
        report = self._match([asset])
        self._notify(report.new_findings)
        return report

    def _match(self, assets: list[Asset]) -> MatchReport:
        report = MatchReport(checked_assets=len(assets))
        vulns = self._s.execute(select(Vulnerability)).scalars().unique().all()
        now = self._clock.now()
        policy = self.policy()
        have = {(f.vulnerability_id, f.asset_id) for f in self._s.execute(
            select(Finding).where(Finding.asset_id.in_([a.id for a in assets]))).scalars().unique()} if assets else set()
        for asset in assets:
            refs = self._software_refs(asset)
            if not refs:
                continue
            for vuln in vulns:
                if (vuln.id, asset.id) in have or not vuln.affected:
                    continue
                for ref in refs:
                    m = matcher.match_software(vuln.affected, ref)
                    if m is not None:
                        if m.confidence == "low" and not any(self.classification(vuln, policy)):
                            continue  # a product-only match is raised only while the flaw is zero-day or zero-hour
                        finding = Finding(vulnerability=vuln, vulnerability_id=vuln.id, asset_id=asset.id,
                                          matched_on=m.matched_on[:160], match_basis=m.basis,
                                          confidence=m.confidence, status="open", first_matched_at=now)
                        self._s.add(finding)
                        have.add((vuln.id, asset.id))
                        report.new_findings.append(finding)
                        break
        self._s.flush()
        return report

    # -- classification and views -------------------------------------------------------------------
    def classification(self, vuln: Vulnerability, policy: IntelPolicy | None = None) -> tuple[bool, bool]:
        p = policy or self.policy()
        return matcher.classify(
            kev=vuln.kev, epss=vuln.epss, fix_status=vuln.fix_status, published_at=vuln.published_at,
            first_seen_at=vuln.first_seen_at, now=self._clock.now(), zero_hour_hours=p.zero_hour_hours,
            epss_threshold=p.epss_threshold)

    def vuln_dto(self, v: Vulnerability, policy: IntelPolicy | None = None, *, detail: bool = False) -> dict[str, Any]:
        zero_day, zero_hour = self.classification(v, policy)
        data = {
            "id": v.id, "vuln_id": v.vuln_id, "title": v.title, "severity": v.severity, "cvss": v.cvss,
            "epss": v.epss, "kev": v.kev, "fix_status": v.fix_status, "is_demo": v.is_demo,
            "published_at": v.published_at.isoformat() if v.published_at else None,
            "first_seen_at": v.first_seen_at.isoformat(), "classification": matcher.label(zero_day, zero_hour),
            "is_zero_day": zero_day, "is_zero_hour": zero_hour, "sources": list(v.sources or []),
        }
        if detail:
            data.update({"description": v.description, "affected": v.affected, "references": v.references})
        return data

    def finding_dto(self, f: Finding, assets: dict[int, Asset], policy: IntelPolicy | None = None) -> dict[str, Any]:
        asset = assets.get(f.asset_id)
        v = self.vuln_dto(f.vulnerability, policy)
        return {
            "id": f.id, "status": f.status, "matched_on": f.matched_on, "match_basis": f.match_basis,
            "confidence": f.confidence,
            "first_matched_at": f.first_matched_at.isoformat(), "acknowledged_by": f.acknowledged_by,
            "acknowledged_at": f.acknowledged_at.isoformat() if f.acknowledged_at else None, "note": f.note,
            "vulnerability": v, "classification": v["classification"],
            "asset": {"id": asset.id, "code": asset.code, "name": asset.name, "zone": asset.zone.code if asset.zone else None,
                      "criticality": asset.criticality} if asset else None,
        }

    def finding_event(self, f: Finding) -> dict[str, Any]:
        zero_day, zero_hour = self.classification(f.vulnerability)
        return {"vuln_id": f.vulnerability.vuln_id, "severity": f.vulnerability.severity,
                "classification": matcher.label(zero_day, zero_hour), "asset_id": f.asset_id}

    def list_findings(self, viewer: Viewer, *, status: str = "", classification: str = "", severity: str = "",
                      asset: str = "", q: str = "", page: int = 1, page_size: int = 20) -> dict[str, Any]:
        self._need(viewer, Cap.INTEL_VIEW)
        page, page_size = max(1, page), min(max(1, page_size), 200)
        policy = self.policy()
        stmt = select(Finding).join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        if status:
            stmt = stmt.where(Finding.status == status)
        if severity:
            stmt = stmt.where(Vulnerability.severity == severity)
        if asset:
            stmt = stmt.where(Finding.asset_id.in_(select(Asset.id).where(Asset.code == asset)))
        if q.strip():
            like = f"%{q.strip().lower()}%"
            stmt = stmt.where(or_(func.lower(Vulnerability.vuln_id).like(like), func.lower(Vulnerability.title).like(like)))
        rows = self._s.execute(stmt.order_by(Finding.id.desc())).scalars().unique().all()
        assets = {a.id: a for a in self._s.execute(select(Asset)).scalars().unique()}
        items = [self.finding_dto(f, assets, policy) for f in rows]
        if classification:
            items = [i for i in items if i["classification"] == classification]
        order = {"zero_day": 0, "zero_hour": 1, "ordinary": 2}
        sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        items.sort(key=lambda i: (order[i["classification"]], sev.get(i["vulnerability"]["severity"], 4), -i["id"]))
        total = len(items)
        return {"items": items[(page - 1) * page_size: page * page_size], "total": total, "page": page,
                "page_size": page_size}

    def update_finding(self, viewer: Viewer, finding_id: int, status: str, note: str) -> dict[str, Any]:
        self._need(viewer, Cap.INTEL_ACK)
        f = self._s.get(Finding, finding_id)
        if f is None:
            raise not_found("intel.finding_not_found")
        if status not in FINDING_STATUSES or len(note) > 500:
            raise invalid("intel.invalid", [{"code": "intel.status_invalid", "fields": ["status", "note"]}])
        before = {"status": f.status, "note": f.note}
        f.status, f.note = status, note
        if status != "open":
            f.acknowledged_by = viewer.ctx.actor.name or "system"
            f.acknowledged_at = self._clock.now()
        else:
            f.acknowledged_by, f.acknowledged_at = "", None
        self._audit.record("intel.finding.update", viewer.ctx, object_type="finding", object_id=f.id,
                           changes=diff(before, {"status": f.status, "note": f.note}),
                           details={"vulnerability": f.vulnerability.vuln_id, "asset_id": f.asset_id})
        assets = {a.id: a for a in self._s.execute(select(Asset).where(Asset.id == f.asset_id)).scalars().unique()}
        return self.finding_dto(f, assets)

    def list_vulnerabilities(self, viewer: Viewer, *, q: str = "", severity: str = "", kev: bool | None = None,
                             classification: str = "", page: int = 1, page_size: int = 20) -> dict[str, Any]:
        self._need(viewer, Cap.INTEL_VIEW)
        page, page_size = max(1, page), min(max(1, page_size), 200)
        policy = self.policy()
        stmt = select(Vulnerability)
        if q.strip():
            like = f"%{q.strip().lower()}%"
            stmt = stmt.where(or_(func.lower(Vulnerability.vuln_id).like(like), func.lower(Vulnerability.title).like(like)))
        if severity:
            stmt = stmt.where(Vulnerability.severity == severity)
        if kev is not None:
            stmt = stmt.where(Vulnerability.kev.is_(kev))
        counts = dict(self._s.execute(
            select(Finding.vulnerability_id, func.count()).group_by(Finding.vulnerability_id)).all())
        rows = self._s.execute(stmt.order_by(Vulnerability.id.desc())).scalars().unique().all()
        items = []
        for v in rows:
            dto = self.vuln_dto(v, policy)
            dto["affected_assets"] = counts.get(v.id, 0)
            if classification and dto["classification"] != classification:
                continue
            items.append(dto)
        total = len(items)
        return {"items": items[(page - 1) * page_size: page * page_size], "total": total, "page": page,
                "page_size": page_size}

    def get_vulnerability(self, viewer: Viewer, vuln_id: str) -> dict[str, Any]:
        self._need(viewer, Cap.INTEL_VIEW)
        v = self._s.execute(select(Vulnerability).where(Vulnerability.vuln_id == vuln_id.upper())).scalar_one_or_none()
        if v is None:
            raise not_found("intel.vulnerability_not_found")
        policy = self.policy()
        assets = {a.id: a for a in self._s.execute(select(Asset)).scalars().unique()}
        data = self.vuln_dto(v, policy, detail=True)
        data["findings"] = [self.finding_dto(f, assets, policy) for f in v.findings]
        return data

    def overview(self, viewer: Viewer) -> dict[str, Any]:
        self._need(viewer, Cap.INTEL_VIEW)
        policy = self.policy()
        open_f = self._s.execute(select(Finding).where(Finding.status == "open")).scalars().unique().all()
        counts = {"zero_day": 0, "zero_hour": 0, "ordinary": 0}
        for f in open_f:
            counts[matcher.label(*self.classification(f.vulnerability, policy))] += 1
        total = self._s.execute(select(func.count()).select_from(Vulnerability)).scalar_one()
        last = self._s.execute(select(func.max(IntelSource.last_run_at))).scalar_one()
        return {"open_findings": counts, "vulnerabilities": total,
                "last_run_at": last.isoformat() if last else None, "policy": policy.to_dict()}

    # -- notification -------------------------------------------------------------------------------
    def _recipients(self) -> list[User]:
        role_ids = [r for (r,) in self._s.execute(
            select(RolePermission.role_id).where(RolePermission.permission == Cap.INTEL_ACK)).all()]
        if not role_ids:
            return []
        return list(self._s.execute(
            select(User).where(User.role_id.in_(role_ids), User.is_active.is_(True), User.email != "",
                               User.is_service.is_(False))).scalars())

    def _notify(self, findings: list[Finding]) -> int:
        """One critical-alert mail per vulnerability and recipient, listing the affected assets."""
        policy = self.policy()
        if not policy.notify or not findings:
            return 0
        floor = SEVERITIES.index(policy.notify_min_severity)
        grouped: dict[int, list[Finding]] = {}
        for f in findings:
            zero_day, zero_hour = self.classification(f.vulnerability, policy)
            if (zero_day or zero_hour) and SEVERITIES.index(f.vulnerability.severity) >= floor and f.notified_at is None:
                grouped.setdefault(f.vulnerability_id, []).append(f)
        if not grouped:
            return 0
        recipients = self._recipients()
        asset_codes = dict(self._s.execute(select(Asset.id, Asset.code)).all())
        now = self._clock.now()
        sent = 0
        for fs in grouped.values():
            v = fs[0].vulnerability
            zero_day, _ = self.classification(v, policy)
            variables = {
                "vulnerability_id": v.vuln_id, "title": v.title or v.vuln_id,
                "classification": "zero-day" if zero_day else "zero-hour", "severity": v.severity,
                "assets": ", ".join(sorted(asset_codes.get(f.asset_id, str(f.asset_id)) for f in fs)),
                "detected_at": now.strftime("%Y-%m-%d %H:%M UTC"),
            }
            for user in recipients:
                if self._mail.queue("alert.critical", user, variables) is not None:
                    sent += 1
            for f in fs:
                f.notified_at = now
        return sent

    # -- running sources ----------------------------------------------------------------------------
    def run_source(self, key: str, fetcher: Fetcher, viewer: Viewer | None = None) -> dict[str, Any]:
        if viewer is not None:
            self._need(viewer, Cap.INTEL_SOURCES_MANAGE)
        self.ensure_sources()
        source = self._s.execute(select(IntelSource).where(IntelSource.key == key)).scalar_one_or_none()
        if source is None:
            raise not_found("intel.source_not_found")
        if self.policy().offline_only:
            raise ApiError(409, "intel.offline_only")
        if not source.url or source.kind == "bundle":
            raise ApiError(409, "intel.source_not_fetchable")
        now = self._clock.now()
        params: dict[str, str] | None = None
        if source.kind == "nvd":
            since = (source.last_run_at or now - timedelta(days=7)).astimezone(timezone.utc)
            since = max(since, now - timedelta(days=119))  # the API accepts at most 120 days
            params = {"lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
                      "lastModEndDate": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")}
        try:
            content = fetcher.get(source.url, params)
            records = PARSERS[source.kind](content)
            report = self._ingest(records, source.key, create_missing=source.kind != "epss")
        except (FetchError, FeedError, ApiError) as exc:
            source.last_run_at, source.last_status = now, "error"
            source.last_error = f"{type(exc).__name__}: {exc}"[:255]
            source.last_items = 0
            return {**self._source_dto(source), "report": None}
        source.last_run_at, source.last_status, source.last_error = now, "ok", ""
        source.last_items = report.created + report.updated
        if viewer is not None:
            self._audit.record("intel.source.run", viewer.ctx, object_type="intel_source", object_id=key,
                               details={"created": report.created, "updated": report.updated})
        return {**self._source_dto(source), "report": asdict(report)}

    def run_due_sources(self, fetcher: Fetcher) -> list[IngestReport]:
        """Called by the worker: fetch every enabled online source whose interval has passed."""
        if self.policy().offline_only:
            return []
        self.ensure_sources()
        now = self._clock.now()
        reports = []
        for s in self._s.execute(select(IntelSource).where(IntelSource.enabled.is_(True))).scalars():
            if s.url and (s.last_run_at is None or now - s.last_run_at >= timedelta(hours=s.interval_hours)):
                result = self.run_source(s.key, fetcher)
                if result.get("report"):
                    reports.append(result["report"])
        return reports

    def purge_demo(self) -> int:
        removed = self._s.query(Vulnerability).filter(Vulnerability.is_demo.is_(True)).delete(synchronize_session=False)
        return int(removed)

