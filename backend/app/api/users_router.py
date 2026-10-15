"""User management endpoints (ARG-005). Rules live in UserService; this layer is thin."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import get_services, viewer
from app.services.container import Services
from app.services.user_service import Viewer

router = APIRouter(prefix="/api/v1", tags=["users"])


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateUser(_Strict):
    username: str = Field(max_length=64)
    email: str = Field(max_length=254)
    full_name: str = Field(default="", max_length=128)
    role: str = Field(max_length=64)
    locale: str = Field(default="en", max_length=8)
    password: str = Field(max_length=1024)
    send_email: bool = True


class UpdateUser(BaseModel):
    """Only listed fields are accepted by the service (no mass assignment); the shape stays open here so the
    service can answer with a specific error for unknown fields."""

    model_config = ConfigDict(extra="allow")


class LockUser(_Strict):
    reason: str = Field(default="", max_length=255)


class ResetPassword(_Strict):
    password: str = Field(max_length=1024)


@router.get("/users")
def list_users(search: str = Query("", max_length=100), role: str = Query("", max_length=64),
               page: int = 1, page_size: int = 20, who: Viewer = Depends(viewer),
               svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.users.list(who, search=search, role=role, page=page, page_size=page_size)


@router.get("/users/roles")
def assignable_roles(who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> list[dict[str, Any]]:
    return svc.users.assignable_roles(who)


@router.post("/users", status_code=201)
def create_user(body: CreateUser, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.users.create(who, username=body.username, email=body.email, full_name=body.full_name,
                            role=body.role, locale=body.locale, password=body.password, send_email=body.send_email)


@router.get("/users/{user_id}")
def get_user(user_id: int, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.users.get(who, user_id)


@router.put("/users/{user_id}")
def update_user(user_id: int, body: UpdateUser, who: Viewer = Depends(viewer),
                svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.users.update(who, user_id, body.model_dump())


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> Response:
    svc.users.delete(who, user_id)
    return Response(status_code=204)


@router.post("/users/{user_id}/lock")
def lock_user(user_id: int, body: LockUser, who: Viewer = Depends(viewer),
              svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.users.lock(who, user_id, body.reason)


@router.post("/users/{user_id}/unlock")
def unlock_user(user_id: int, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.users.unlock(who, user_id)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: int, body: ResetPassword, who: Viewer = Depends(viewer),
                   svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.users.reset_password(who, user_id, body.password)
