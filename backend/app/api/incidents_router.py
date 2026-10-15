"""Hybrid incidents: list, detail, workflow and the graph of one incident (ARG-017, ARG-018, ARG-019)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import get_services, viewer
from app.core.errors import forbidden
from app.core.permissions import Cap
from app.services.container import Services
from app.services.user_service import Viewer

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class StatusBody(_Strict):
    status: str = Field(max_length=16)
    note: str = Field(default="", max_length=500)


class NoteBody(_Strict):
    text: str = Field(max_length=1000)


@router.get("")
def list_incidents(status: str = Query("", max_length=16), severity: str = Query("", max_length=12),
                   type: str = Query("", max_length=12), active: bool = False, page: int = 1, page_size: int = 20,
                   who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.incidents.list(who, status=status, severity=severity, type_=type, active_only=active, page=page,
                              page_size=page_size)


@router.get("/overview")
def overview(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.incidents.overview(who)


@router.post("/run")
def run(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    """Evaluate the correlation now (it also runs after every ingestion and on the worker pass)."""
    if not who.has(Cap.INCIDENT_TRIAGE):
        raise forbidden()
    report = svc.incidents.run(force=True)
    svc.publish_incidents(report)
    return {"created": [i.id for i in report.created], "updated": [i.id for i in report.updated]}


@router.get("/{incident_id}")
def get_incident(incident_id: int, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.incidents.get(who, incident_id)


@router.get("/{incident_id}/graph")
def graph(incident_id: int, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.incidents.graph(who, incident_id)


@router.post("/{incident_id}/status")
def status(incident_id: int, body: StatusBody, who: Viewer = Depends(viewer),
           svc: Services = Depends(get_services)) -> dict[str, Any]:
    result = svc.incidents.set_status(who, incident_id, body.status, body.note)
    svc.hub.publish({"type": "incident", "incident": svc.incidents.dto(svc.incidents._load(incident_id))})  # noqa: SLF001
    return result


@router.post("/{incident_id}/escalate")
def escalate(incident_id: int, body: NoteBody, who: Viewer = Depends(viewer),
             svc: Services = Depends(get_services)) -> dict[str, Any]:
    result = svc.incidents.escalate(who, incident_id, body.text)
    svc.hub.publish({"type": "incident", "incident": svc.incidents.dto(svc.incidents._load(incident_id))})  # noqa: SLF001
    return result


@router.post("/{incident_id}/notes")
def note(incident_id: int, body: NoteBody, who: Viewer = Depends(viewer),
         svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.incidents.add_note(who, incident_id, body.text)
