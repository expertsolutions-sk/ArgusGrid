"""Device-facing endpoints. Authentication is a signed request, never a user session (ARG-013)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import device_auth, get_services
from app.services.container import Services
from app.services.device_credentials import DeviceIdentity

router = APIRouter(prefix="/api/v1/ingest", tags=["devices"])


class Heartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(default="ok", max_length=32)


@router.post("/heartbeat")
def heartbeat(body: Heartbeat, identity: DeviceIdentity = Depends(device_auth("ingest:heartbeat")),
              svc: Services = Depends(get_services)) -> dict[str, Any]:
    """A device reports that it is alive. It can only ever speak for its own asset."""
    return {"ok": True, "asset": identity.asset_code, "server_time": svc.clock.now().isoformat()}
