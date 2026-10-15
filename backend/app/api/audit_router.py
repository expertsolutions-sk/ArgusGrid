"""Audit log viewing and export."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

from app.api.deps import get_services, viewer
from app.core.errors import forbidden
from app.core.permissions import Cap
from app.services.audit_query import parse_time
from app.services.container import Services
from app.services.user_service import Viewer

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


def _filters(date_from: str | None, date_to: str | None, actor: str, action: str, object_type: str,
             result: str, q: str) -> dict[str, Any]:
    return {"date_from": parse_time(date_from), "date_to": parse_time(date_to), "actor": actor.strip(),
            "action": action.strip(), "object_type": object_type.strip(), "result": result.strip(), "q": q.strip()}


@router.get("")
def list_audit(date_from: str | None = None, date_to: str | None = None, actor: str = Query("", max_length=64),
               action: str = Query("", max_length=64), object_type: str = Query("", max_length=48),
               result: str = Query("", max_length=16), q: str = Query("", max_length=100),
               page: int = 1, page_size: int = 50, who: Viewer = Depends(viewer),
               svc: Services = Depends(get_services)) -> dict[str, Any]:
    f = _filters(date_from, date_to, actor, action, object_type, result, q)
    return svc.audit_query.page(who, f, page, page_size)


@router.get("/export")
def export_audit(date_from: str | None = None, date_to: str | None = None, actor: str = Query("", max_length=64),
                 action: str = Query("", max_length=64), object_type: str = Query("", max_length=48),
                 result: str = Query("", max_length=16), q: str = Query("", max_length=100),
                 who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> PlainTextResponse:
    f = _filters(date_from, date_to, actor, action, object_type, result, q)
    content = svc.audit_query.export_csv(who, f)
    svc.audit.record("audit.export", who.ctx, object_type="audit", details={"filters": {k: str(v) for k, v in f.items() if v}})
    if svc.profile.marking:  # the marking travels with the data (ARG-021)
        content = "# " + svc.profile.marking + chr(10) + content
    return PlainTextResponse(
        content, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="argusgrid-audit.csv"'},
    )


@router.get("/verify")
def verify(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, bool]:
    if not who.has(Cap.AUDIT_VIEW):
        raise forbidden()
    return {"intact": svc.audit.verify_chain()}
