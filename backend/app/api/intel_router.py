"""Threat intelligence: findings, vulnerabilities, sources, import, policy and trust (ARG-016)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import get_services, viewer
from app.core.errors import ApiError, forbidden
from app.core.permissions import Cap
from app.services.container import Services
from app.services.user_service import Viewer

router = APIRouter(prefix="/api/v1/intel", tags=["intel"])


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FindingUpdate(_Strict):
    status: str = Field(max_length=16)
    note: str = Field(default="", max_length=500)


class SourceUpdate(_Strict):
    enabled: bool | None = None
    url: str | None = Field(default=None, max_length=512)
    interval_hours: int | None = None


class ImportBody(_Strict):
    format: str = Field(max_length=16)
    payload: Any


class PolicyBody(_Strict):
    zero_hour_hours: int
    epss_threshold: float
    notify_min_severity: str = Field(max_length=12)
    notify: bool
    offline_only: bool


class KeyItem(_Strict):
    key_id: str = Field(max_length=64)
    public_key: str = Field(max_length=100)
    label: str = Field(default="", max_length=64)


class KeysBody(_Strict):
    keys: list[KeyItem] = Field(max_length=20)


@router.get("/overview")
def overview(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.intel.overview(who)


@router.get("/findings")
def findings(status: str = Query("", max_length=16), classification: str = Query("", max_length=16),
             severity: str = Query("", max_length=12), asset: str = Query("", max_length=48),
             q: str = Query("", max_length=100), page: int = 1, page_size: int = 20,
             who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.intel.list_findings(who, status=status, classification=classification, severity=severity,
                                   asset=asset, q=q, page=page, page_size=page_size)


@router.put("/findings/{finding_id}")
def update_finding(finding_id: int, body: FindingUpdate, who: Viewer = Depends(viewer),
                   svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.intel.update_finding(who, finding_id, body.status, body.note)


@router.get("/vulnerabilities")
def vulnerabilities(q: str = Query("", max_length=100), severity: str = Query("", max_length=12),
                    kev: bool | None = None, classification: str = Query("", max_length=16),
                    page: int = 1, page_size: int = 20, who: Viewer = Depends(viewer),
                    svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.intel.list_vulnerabilities(who, q=q, severity=severity, kev=kev, classification=classification,
                                          page=page, page_size=page_size)


@router.get("/vulnerabilities/{vuln_id}")
def vulnerability(vuln_id: str, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.intel.get_vulnerability(who, vuln_id)


@router.get("/sources")
def sources(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> list[dict[str, Any]]:
    if not who.has(Cap.INTEL_VIEW):
        raise forbidden()
    return svc.intel.sources()


@router.put("/sources/{key}")
def update_source(key: str, body: SourceUpdate, who: Viewer = Depends(viewer),
                  svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.intel.update_source(who, key, body.model_dump(exclude_none=True))


@router.post("/sources/{key}/run")
def run_source(key: str, request: Request, who: Viewer = Depends(viewer),
               svc: Services = Depends(get_services)) -> dict[str, Any]:
    result = svc.intel.run_source(key, request.app.state.fetcher, who)
    report = result.get("report")
    if report and report.get("findings"):
        svc.hub.publish({"type": "intel", "findings": report["findings"]})
    return result


@router.post("/import")
def import_feed(body: ImportBody, request: Request, who: Viewer = Depends(viewer),
                svc: Services = Depends(get_services)) -> dict[str, Any]:
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > 30 * 1024 * 1024:
        raise ApiError(413, "intel.too_large")
    report = svc.intel.import_payload(who, body.format, body.payload, source_key="manual")
    if report.findings:
        svc.hub.publish({"type": "intel", "findings": report.findings})
    svc.publish_incidents(svc.incidents.run(force=True))
    return {"created": report.created, "updated": report.updated, "skipped": report.skipped,
            "new_findings": report.new_findings, "notified": report.notified}


@router.post("/rematch")
def rematch(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    if not who.has(Cap.INTEL_SOURCES_MANAGE):
        raise forbidden()
    report = svc.intel.match_all()
    notified = svc.intel._notify(report.new_findings)  # noqa: SLF001 (same service family)
    svc.audit.record("intel.rematch", who.ctx, object_type="intel", object_id="all",
                     details={"new_findings": len(report.new_findings)})
    return {"checked_assets": report.checked_assets, "new_findings": len(report.new_findings), "notified": notified}


@router.get("/policy")
def get_policy(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    if not who.has(Cap.INTEL_VIEW):
        raise forbidden()
    return svc.intel.policy().to_dict()


@router.put("/policy")
def put_policy(body: PolicyBody, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    if not who.has(Cap.INTEL_SOURCES_MANAGE):
        raise forbidden()
    from app.services.audit_service import diff

    before = svc.intel.policy().to_dict()
    updated = svc.intel.update_policy(body.model_dump(), who.ctx.actor.name or "system")
    svc.audit.record("intel.policy.update", who.ctx, object_type="intel", object_id="policy",
                     changes=diff(before, updated.to_dict()))
    return updated.to_dict()


@router.get("/trusted-keys")
def get_keys(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> list[dict[str, str]]:
    if not who.has(Cap.INTEL_SOURCES_MANAGE):
        raise forbidden()
    return svc.intel.trusted_keys()


@router.put("/trusted-keys")
def put_keys(body: KeysBody, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> list[dict[str, str]]:
    if not who.has(Cap.INTEL_SOURCES_MANAGE):
        raise forbidden()
    keys = svc.intel.set_trusted_keys([k.model_dump() for k in body.keys], who.ctx.actor.name or "system")
    svc.audit.record("intel.trusted_keys.update", who.ctx, object_type="intel", object_id="trusted_keys",
                     details={"key_ids": [k["key_id"] for k in keys]})
    return keys
