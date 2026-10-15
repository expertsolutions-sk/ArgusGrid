"""Authentication endpoints: login, logout, session info, change password (IDN-001)."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Request, Response

from app.api.deps import (
    COOKIE_NAME,
    Principal,
    build_context,
    get_services,
    optional_principal,
    principal_pending_ok,
    request_context,
)
from app.api.schemas import ChangePasswordRequest, LoginRequest, ProfileInfo, SessionInfo, UserInfo
from app.core.context import Actor, RequestContext
from app.core.errors import ApiError
from app.services.container import Services
from app.services.profile import Profile

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _dev_banner(active: bool) -> str:
    """The banner text comes from the development-only module, so no package contains it (DEV-006)."""
    if not active:
        return ""
    try:
        from app import dev_loginless
    except ImportError:  # pragma: no cover - the module is removed from packages
        return ""
    return dev_loginless.BANNER


def session_info(principal: Principal | None, profile: Profile | None = None) -> SessionInfo:
    info = _session_info(principal)
    if profile is not None:
        info.profile = ProfileInfo(**profile.public())
    return info


def _session_info(principal: Principal | None) -> SessionInfo:
    if principal is None:
        return SessionInfo(authenticated=False)
    if principal.is_owner:
        # The owner sees everything; the existence of this account is never exposed to others (OWN-002).
        return SessionInfo(
            authenticated=True,
            user=UserInfo(username="", full_name="", role=""),
            csrf_token=principal.session.csrf_token if principal.session else None,
            capabilities=["*"],
        )
    user = principal.user
    assert user is not None
    return SessionInfo(
        authenticated=True,
        user=UserInfo(username=user.username, full_name=user.full_name, role=user.role.name, email=user.email),
        csrf_token=principal.session.csrf_token if principal.session else None,
        must_change_password=user.must_change_password,
        capabilities=sorted(principal.capabilities),
        dev_loginless=principal.dev_loginless,
        dev_banner=_dev_banner(principal.dev_loginless),
        password_expires_at=user.password_expires_at.isoformat() if user.password_expires_at else None,
    )


@router.post("/login", response_model=SessionInfo)
def login(body: LoginRequest, request: Request, response: Response,
          svc: Services = Depends(get_services)) -> SessionInfo:
    ctx = build_context(request)
    throttle = request.app.state.throttle
    limit = svc.lockout_settings.get().source_throttle_per_minute
    if not throttle.allow(ctx.source_ip, limit, time.monotonic()):
        svc.audit.record("auth.login_throttled", ctx, result="failure", reason="source_throttle")
        raise ApiError(429, "too_many_requests")
    result = svc.auth.login(body.username, body.password, ctx)
    response.set_cookie(
        COOKIE_NAME, result.token, httponly=True, samesite="strict", secure=svc.config.secure_cookies, path="/",
    )
    user = result.user
    if user is None:
        actor = Actor(kind="owner", name="System")
        principal = Principal(actor=actor, user=None, session=result.session, capabilities=frozenset(),
                              is_owner=True)
    else:
        actor = Actor(kind="user", name=user.username, role=user.role.name, user_id=user.id)
        principal = Principal(actor=actor, user=user, session=result.session,
                              capabilities=frozenset(user.role.capabilities))
    return session_info(principal, svc.profile)


@router.post("/logout", status_code=204)
def logout(response: Response, principal: Principal = Depends(principal_pending_ok),
           ctx: RequestContext = Depends(request_context), svc: Services = Depends(get_services)) -> Response:
    if principal.session is not None:
        svc.auth.logout(principal.session, ctx)
    response.delete_cookie(COOKIE_NAME, path="/")
    response.status_code = 204
    return response


@router.get("/session", response_model=SessionInfo)
def session(principal: Principal | None = Depends(optional_principal),
            svc: Services = Depends(get_services)) -> SessionInfo:
    return session_info(principal, svc.profile)


@router.post("/change-password", status_code=204)
def change_password(body: ChangePasswordRequest, principal: Principal = Depends(principal_pending_ok),
                    ctx: RequestContext = Depends(request_context),
                    svc: Services = Depends(get_services)) -> Response:
    if principal.user is None or principal.session is None:
        raise ApiError(403, "owner_has_no_password")
    svc.auth.change_password(principal.user, principal.session, body.current_password, body.new_password, ctx)
    return Response(status_code=204)
