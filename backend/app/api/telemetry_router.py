"""Telemetry ingestion (devices), live stream and read APIs (ARG-014, ARG-015)."""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import COOKIE_NAME, device_auth, get_services, viewer
from app.core.context import RequestContext
from app.core.errors import forbidden
from app.core.permissions import Cap
from app.models.identity import User
from app.services.container import Services
from app.services.device_credentials import DeviceIdentity
from app.services.telemetry_service import MAX_BATCH
from app.services.user_service import Viewer

router = APIRouter(prefix="/api/v1", tags=["telemetry"])


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(max_length=16)
    type: str = Field(default="detection", max_length=16)
    ts: str | None = Field(default=None, max_length=40)
    track_id: str | None = Field(default=None, max_length=64)
    x: float | None = None
    y: float | None = None
    altitude: float | None = None
    speed: float | None = None
    heading: float | None = None
    confidence: float | None = None
    severity: str | None = Field(default=None, max_length=12)
    data: dict[str, Any] = Field(default_factory=dict)


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[EventIn] = Field(min_length=1, max_length=MAX_BATCH)


@router.post("/ingest/events")
def ingest_events(request_body: EventBatch, identity: DeviceIdentity = Depends(device_auth("ingest:heartbeat")),
                  svc: Services = Depends(get_services)) -> dict[str, Any]:
    """A device reports events. Each event is stored against the authenticated device's own asset."""
    result = svc.telemetry.ingest(identity, [e.model_dump() for e in request_body.events])
    if any("event.scope_missing" in r["codes"] for r in result.rejected):
        from app.core.context import ANONYMOUS_ACTOR

        svc.audit.record("device.scope_violation", RequestContext(actor=ANONYMOUS_ACTOR, channel="service"),
                         object_type="asset", object_id=identity.asset_id, result="failure",
                         details={"key_id": identity.key_id})
    if result.messages:
        svc.session.flush()
        svc.hub.publish({"type": "telemetry", "events": result.messages})
        svc.publish_incidents(svc.incidents.run())  # correlation after each batch (rate limited)
    return {"accepted": result.accepted, "rejected": result.rejected}


# -- reading ----------------------------------------------------------------------------------------
@router.get("/telemetry/state")
def state(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    if not who.has(Cap.ASSET_VIEW):
        raise forbidden()
    return svc.telemetry.state()


@router.get("/telemetry/tracks/{track_id}")
def track(track_id: str, minutes: int = 30, who: Viewer = Depends(viewer),
          svc: Services = Depends(get_services)) -> list[dict[str, Any]]:
    if not who.has(Cap.ASSET_VIEW):
        raise forbidden()
    return svc.telemetry.track_history(track_id, minutes=min(max(1, minutes), 24 * 60))


@router.get("/telemetry/events")
def events(kind: str = Query("", max_length=16), severity: str = Query("", max_length=12),
           track_id: str = Query("", max_length=64), minutes: int = 60, page: int = 1, page_size: int = 50,
           who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    if not who.has(Cap.ASSET_VIEW):
        raise forbidden()
    return svc.telemetry.events(kind=kind, severity=severity, track_id=track_id, minutes=minutes, page=page,
                                page_size=page_size)


@router.get("/site")
def site(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    """Static site picture for the map: zones, buildings, gates and the airspace rings."""
    if not who.has(Cap.ASSET_VIEW):
        raise forbidden()
    try:
        from app.demo import krec  # not part of the production package
    except ImportError:
        krec = None

    zones = svc.assets.zones(who)
    has_demo = krec is not None and any(z["code"] == "Z2" for z in zones)
    if has_demo:
        width, height = krec.SITE["width_m"], krec.SITE["height_m"]
    else:  # the extent of the zones the operator has defined
        points = [p for z in zones for p in (z.get("polygon") or [])]
        width = max((p[0] for p in points), default=1000)
        height = max((p[1] for p in points), default=700)
    return {
        "name": krec.SITE["name"] if has_demo else "Site",
        "width_m": width, "height_m": height,
        "zones": zones, "buildings": krec.BUILDINGS if has_demo else [], "gates": krec.GATES if has_demo else [],
        "airspace": svc.airspace.get().to_dict(),
    }


class AirspaceBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    centre_x: float
    centre_y: float
    alert_m: float
    warning_m: float
    critical_m: float
    ceiling_m: float


@router.put("/settings/airspace")
def put_airspace(body: AirspaceBody, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    if not who.has(Cap.ASSET_EDIT):
        raise forbidden()
    before = svc.airspace.get().to_dict()
    updated = svc.airspace.update(body.model_dump(), who.ctx.actor.name or "system")
    from app.services.audit_service import diff

    svc.audit.record("settings.airspace.update", who.ctx, object_type="settings", object_id="airspace",
                     changes=diff(before, updated.to_dict()))
    return updated.to_dict()


# -- live stream ------------------------------------------------------------------------------------
@router.websocket("/stream")
async def stream(websocket: WebSocket) -> None:
    """Live telemetry. Authenticated by the session cookie, same-origin only, needs `asset.view`."""
    app = websocket.app
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host", "")
    if origin and urlparse(origin).netloc != host:
        await websocket.close(code=4403)
        return

    def authenticate() -> bool:
        session = app.state.db.session()
        try:
            svc = Services(session, app.state.clock, app.state.config, app.state.transport, app.state.replay,
                           app.state.hub)
            row = svc.sessions.resolve(websocket.cookies.get(COOKIE_NAME))
            if row is None:
                return False
            if row.is_owner:
                return True
            user = session.get(User, row.user_id) if row.user_id is not None else None
            if user is None or not user.is_active or svc.lockout.is_locked(user) or user.must_change_password:
                return False
            session.commit()
            return Cap.ASSET_VIEW in user.role.capabilities
        finally:
            session.close()

    if not await asyncio.to_thread(authenticate):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    hub = app.state.hub
    hub.bind(asyncio.get_running_loop())
    queue = hub.subscribe()
    try:
        await websocket.send_json({"type": "hello"})
        while True:
            receive = asyncio.create_task(websocket.receive_text())
            fetch = asyncio.create_task(queue.get())
            done, pending = await asyncio.wait({receive, fetch}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            if receive in done:
                receive.result()  # raises WebSocketDisconnect when the client leaves
                continue
            await websocket.send_json(fetch.result())
    except WebSocketDisconnect:
        pass
    finally:
        hub.unsubscribe(queue)

