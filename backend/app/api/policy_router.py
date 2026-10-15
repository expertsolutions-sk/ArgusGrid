"""Policy read endpoints for every authenticated user, and the settings pages for administrators."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from app.api.deps import Principal, get_services, principal_pending_ok, request_context, require
from app.api.schemas import GeneratedPassword, PolicyEnvelope, SettingsBody
from app.core.context import RequestContext
from app.core.permissions import Cap
from app.services.audit_service import diff
from app.services.container import Services
from app.services import policy_service as pw

router = APIRouter(prefix="/api/v1", tags=["policy"])


# -- available to every authenticated user (PasswordField needs them, also during a forced change) -------
@router.get("/policy/password/summary")
def password_summary(_: Principal = Depends(principal_pending_ok), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.policy.summary()


@router.post("/policy/password/generate", response_model=GeneratedPassword)
def generate_password(principal: Principal = Depends(principal_pending_ok),
                      svc: Services = Depends(get_services)) -> GeneratedPassword:
    return GeneratedPassword(password=svc.credentials.generate_password(principal.actor.name))


# -- settings pages ------------------------------------------------------------------------------------
def _password_limits() -> dict[str, Any]:
    return {
        "floor_min_length": pw.FLOOR_MIN_LENGTH,
        "ceiling_max_length": pw.CEILING_MAX_LENGTH,
        "max_history": pw.MAX_HISTORY,
        "max_expiry_months": pw.MAX_EXPIRY_MONTHS,
        "max_min_age_hours": pw.MAX_MIN_AGE_HOURS,
        "max_reveal_seconds": pw.MAX_REVEAL_SECONDS,
    }


@router.get("/settings/password-policy", response_model=PolicyEnvelope)
def get_password_policy(_: Principal = Depends(require(Cap.POLICY_PASSWORD_VIEW)),
                        svc: Services = Depends(get_services)) -> PolicyEnvelope:
    return PolicyEnvelope(policy=svc.policy.get().to_dict(), limits=_password_limits())


@router.put("/settings/password-policy", response_model=PolicyEnvelope)
def put_password_policy(body: SettingsBody, principal: Principal = Depends(require(Cap.POLICY_PASSWORD_EDIT)),
                        ctx: RequestContext = Depends(request_context),
                        svc: Services = Depends(get_services)) -> PolicyEnvelope:
    before = svc.policy.get().to_dict()
    updated = svc.policy.update(body.model_dump(), principal.actor.name)
    svc.audit.record("policy.password.update", ctx, object_type="policy", object_id="password",
                     changes=diff(before, updated.to_dict()))
    return PolicyEnvelope(policy=updated.to_dict(), limits=_password_limits())


@router.get("/settings/lockout")
def get_lockout(_: Principal = Depends(require(Cap.POLICY_LOCKOUT_VIEW)),
                svc: Services = Depends(get_services)) -> dict[str, Any]:
    settings = svc.lockout_settings.get()
    levels = svc.roles.levels()
    return {"settings": settings.to_dict(), "roles": levels}


@router.put("/settings/lockout")
def put_lockout(body: SettingsBody, principal: Principal = Depends(require(Cap.POLICY_LOCKOUT_EDIT)),
                ctx: RequestContext = Depends(request_context),
                svc: Services = Depends(get_services)) -> dict[str, Any]:
    before = svc.lockout_settings.get().to_dict()
    updated = svc.lockout_settings.update(body.model_dump(), svc.roles.levels(), principal.actor.name)
    svc.audit.record("policy.lockout.update", ctx, object_type="policy", object_id="lockout",
                     changes=diff(before, updated.to_dict()))
    return {"settings": updated.to_dict(), "roles": svc.roles.levels()}


@router.get("/settings/session")
def get_session_policy(_: Principal = Depends(require(Cap.POLICY_SESSION_VIEW)),
                       svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.session_policy.get().to_dict()


@router.put("/settings/session")
def put_session_policy(body: SettingsBody, principal: Principal = Depends(require(Cap.POLICY_SESSION_EDIT)),
                       ctx: RequestContext = Depends(request_context),
                       svc: Services = Depends(get_services)) -> dict[str, Any]:
    before = svc.session_policy.get().to_dict()
    updated = svc.session_policy.update(body.model_dump(), principal.actor.name)
    svc.audit.record("policy.session.update", ctx, object_type="policy", object_id="session",
                     changes=diff(before, updated.to_dict()))
    return updated.to_dict()
