"""Asset registry, relations, software, zones, topology and device credentials (management side)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import get_services, viewer
from app.services.container import Services
from app.services.user_service import Viewer

router = APIRouter(prefix="/api/v1", tags=["assets"])


class _Open(BaseModel):
    """Field validation is done by the service (it names every problem); the shape stays open here."""

    model_config = ConfigDict(extra="allow")


class SoftwareItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(max_length=200)
    vendor: str = Field(default="", max_length=200)
    version: str = Field(default="", max_length=200)
    cpe: str = Field(default="", max_length=400)


class SoftwareBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[SoftwareItem] = Field(max_length=500)


class RelationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(max_length=64)
    relation: str = Field(max_length=32)
    protocol: str = Field(default="", max_length=100)
    note: str = Field(default="", max_length=400)
    direction: str = Field(default="outgoing", pattern="^(outgoing|incoming)$")


class CredentialBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scopes: list[str] = Field(max_length=20)
    allowed_networks: list[str] = Field(max_length=20)
    valid_days: int = 90


class RotateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    grace_minutes: int = 0


@router.get("/assets/vocabulary")
def vocabulary(_: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.assets.vocabulary()


@router.get("/zones")
def zones(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> list[dict[str, Any]]:
    return svc.assets.zones(who)


@router.get("/assets/topology")
def topology(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.assets.topology(who)


@router.get("/assets")
def list_assets(search: str = Query("", max_length=100), asset_type: str = Query("", max_length=24),
                zone: str = Query("", max_length=16), status: str = Query("", max_length=16),
                level: str = Query("", max_length=4), category: str = Query("", max_length=16),
                page: int = 1, page_size: int = 20, who: Viewer = Depends(viewer),
                svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.assets.list(who, search=search, asset_type=asset_type, zone=zone, status=status, level=level,
                           category=category, page=page, page_size=page_size)


@router.post("/assets", status_code=201)
def create_asset(body: _Open, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.assets.create(who, body.model_dump())


@router.get("/assets/{asset_id}")
def get_asset(asset_id: int, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.assets.get(who, asset_id)


@router.put("/assets/{asset_id}")
def update_asset(asset_id: int, body: _Open, who: Viewer = Depends(viewer),
                 svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.assets.update(who, asset_id, body.model_dump())


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: int, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> Response:
    svc.assets.delete(who, asset_id)
    return Response(status_code=204)


@router.put("/assets/{asset_id}/software")
def put_software(asset_id: int, body: SoftwareBody, who: Viewer = Depends(viewer),
                 svc: Services = Depends(get_services)) -> dict[str, Any]:
    result = svc.assets.set_software(who, asset_id, [i.model_dump() for i in body.items])
    # a changed inventory is matched against the known vulnerabilities at once
    from app.models.assets import Asset

    asset = svc.session.get(Asset, asset_id)
    if asset is not None:
        report = svc.intel.match_asset(asset)
        if report.new_findings:
            svc.hub.publish({"type": "intel", "findings": [svc.intel.finding_event(f) for f in report.new_findings]})
    return result


@router.post("/assets/{asset_id}/relations", status_code=201)
def add_relation(asset_id: int, body: RelationBody, who: Viewer = Depends(viewer),
                 svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.assets.add_relation(who, asset_id, target_code=body.target, relation=body.relation,
                                   protocol=body.protocol, note=body.note, direction=body.direction)


@router.delete("/assets/{asset_id}/relations/{relation_id}")
def remove_relation(asset_id: int, relation_id: int, who: Viewer = Depends(viewer),
                    svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.assets.remove_relation(who, asset_id, relation_id)


# -- device credentials ------------------------------------------------------------------------------
@router.get("/assets/{asset_id}/credentials")
def list_credentials(asset_id: int, who: Viewer = Depends(viewer),
                     svc: Services = Depends(get_services)) -> list[dict[str, Any]]:
    return svc.devices.list_for_asset(who, asset_id)


@router.post("/assets/{asset_id}/credentials", status_code=201)
def create_credential(asset_id: int, body: CredentialBody, who: Viewer = Depends(viewer),
                      svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.devices.create(who, asset_id, scopes=body.scopes, allowed_networks=body.allowed_networks,
                              valid_days=body.valid_days)


@router.post("/credentials/{key_id}/rotate")
def rotate_credential(key_id: str, body: RotateBody, who: Viewer = Depends(viewer),
                      svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.devices.rotate(who, key_id, grace_minutes=body.grace_minutes)


@router.post("/credentials/{key_id}/revoke")
def revoke_credential(key_id: str, who: Viewer = Depends(viewer),
                      svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.devices.revoke(who, key_id)
