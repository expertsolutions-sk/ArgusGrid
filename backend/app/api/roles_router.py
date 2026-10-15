"""Role and capability administration endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import get_services, viewer
from app.services.container import Services
from app.services.user_service import Viewer

router = APIRouter(prefix="/api/v1/roles", tags=["roles"])


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UpdateRole(_Strict):
    description: str | None = Field(default=None, max_length=255)
    capabilities: list[str] | None = None


class CreateRole(_Strict):
    name: str = Field(max_length=64)
    description: str = Field(default="", max_length=255)
    security_level: int
    capabilities: list[str] = []


@router.get("")
def list_roles(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return {"roles": svc.role_admin.list(who), "capabilities": svc.role_admin.catalogue()}


@router.post("", status_code=201)
def create_role(body: CreateRole, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.role_admin.create(who, body.name, body.description, body.security_level, body.capabilities)


@router.put("/{role_id}")
def update_role(role_id: int, body: UpdateRole, who: Viewer = Depends(viewer),
                svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.role_admin.update(who, role_id, body.description, body.capabilities)


@router.delete("/{role_id}", status_code=204)
def delete_role(role_id: int, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> Response:
    svc.role_admin.delete(who, role_id)
    return Response(status_code=204)
