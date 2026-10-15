"""E-mail settings, templates and outbox (ARG-007, ARG-008)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import Principal, get_services, request_context, require, viewer
from app.core.context import RequestContext
from app.core.errors import ApiError, forbidden
from app.core.permissions import Cap
from app.services.audit_service import diff
from app.services.container import Services
from app.services.user_service import Viewer

router = APIRouter(prefix="/api/v1/settings/email", tags=["email"])


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmailSettingsBody(_Strict):
    enabled: bool | None = None
    host: str | None = Field(default=None, max_length=254)
    port: int | None = None
    tls_mode: str | None = Field(default=None, max_length=16)
    username: str | None = Field(default=None, max_length=254)
    password: str | None = Field(default=None, max_length=1024)
    clear_password: bool | None = None
    from_address: str | None = Field(default=None, max_length=254)
    from_name: str | None = Field(default=None, max_length=128)
    login_url: str | None = Field(default=None, max_length=254)


class TemplateBody(_Strict):
    subject: str = Field(max_length=255)
    body_text: str = Field(max_length=20000)
    body_html: str = Field(default="", max_length=40000)


class TestBody(_Strict):
    to: str | None = Field(default=None, max_length=254)


@router.get("")
def get_settings(_: Principal = Depends(require(Cap.EMAIL_VIEW)), svc: Services = Depends(get_services)) -> dict[str, Any]:
    return svc.email_settings.get_public()


@router.put("")
def put_settings(body: EmailSettingsBody, principal: Principal = Depends(require(Cap.EMAIL_EDIT)),
                 ctx: RequestContext = Depends(request_context), svc: Services = Depends(get_services)) -> dict[str, Any]:
    before = svc.email_settings.get_public()
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    after = svc.email_settings.update(data, principal.actor.name)
    svc.audit.record("settings.email.update", ctx, object_type="settings", object_id="email",
                     changes=diff(before, after))
    return after


@router.post("/test")
def send_test(body: TestBody, who: Viewer = Depends(viewer), svc: Services = Depends(get_services)) -> dict[str, Any]:
    if not who.has(Cap.EMAIL_EDIT):
        raise forbidden()
    if who.user_id is None:
        raise ApiError(422, "email.test_needs_address")
    from app.models.identity import User

    user = svc.session.get(User, who.user_id)
    assert user is not None
    target = (body.to or user.email).strip()
    if not target:
        raise ApiError(422, "email.test_needs_address")
    if not svc.mail.configured():
        raise ApiError(409, "email.not_configured")
    row = svc.mail.queue("system.test", user, {}, to=target)
    assert row is not None
    report = svc.mail.send_pending(svc.transport)  # deliver now so the page can show the real result
    svc.audit.record("settings.email.test", who.ctx, object_type="settings", object_id="email")
    outbox = svc.session.get(type(row), row.id)
    assert outbox is not None
    return {"status": outbox.status, "error": outbox.last_error, "sent": report.sent}


@router.get("/outbox")
def outbox(limit: int = Query(50, ge=1, le=200), _: Principal = Depends(require(Cap.EMAIL_VIEW)),
           svc: Services = Depends(get_services)) -> list[dict[str, Any]]:
    return svc.mail.recent(limit)


@router.get("/templates")
def templates(_: Principal = Depends(require(Cap.EMAIL_VIEW)), svc: Services = Depends(get_services)) -> list[dict[str, Any]]:
    return svc.templates.catalogue()


@router.get("/templates/{key}")
def template(key: str, locale: str = Query("en", max_length=8), _: Principal = Depends(require(Cap.EMAIL_VIEW)),
             svc: Services = Depends(get_services)) -> dict[str, Any]:
    t = svc.templates.effective(key, locale)
    from app.services import mail_templates as mt

    return {"key": t.key, "locale": t.locale, "subject": t.subject, "body_text": t.body_text, "body_html": t.body_html,
            "version": t.version, "customized": t.customized, "variables": list(mt.SPECS[key].variables),
            "versions": svc.templates.versions(key, t.locale)}


@router.put("/templates/{key}")
def save_template(key: str, body: TemplateBody, locale: str = Query("en", max_length=8),
                  principal: Principal = Depends(require(Cap.EMAIL_TEMPLATES_EDIT)),
                  ctx: RequestContext = Depends(request_context), svc: Services = Depends(get_services)) -> dict[str, Any]:
    before = svc.templates.effective(key, locale)
    saved = svc.templates.update(key, locale, body.subject, body.body_text, body.body_html, principal.actor.name)
    svc.audit.record(
        "settings.email.template.update", ctx, object_type="email_template", object_id=f"{key}:{saved.locale}",
        changes=diff({"subject": before.subject, "body_text": before.body_text, "body_html": before.body_html},
                     {"subject": saved.subject, "body_text": saved.body_text, "body_html": saved.body_html}),
    )
    return {"key": saved.key, "locale": saved.locale, "version": saved.version, "customized": True}


@router.delete("/templates/{key}", status_code=204)
def reset_template(key: str, locale: str = Query("en", max_length=8),
                   _: Principal = Depends(require(Cap.EMAIL_TEMPLATES_EDIT)),
                   ctx: RequestContext = Depends(request_context), svc: Services = Depends(get_services)) -> Response:
    svc.templates.reset(key, locale)
    svc.audit.record("settings.email.template.reset", ctx, object_type="email_template", object_id=f"{key}:{locale}")
    return Response(status_code=204)


@router.post("/templates/{key}/preview")
def preview(key: str, body: TemplateBody, locale: str = Query("en", max_length=8),
            _: Principal = Depends(require(Cap.EMAIL_VIEW)), svc: Services = Depends(get_services)) -> dict[str, str]:
    return svc.templates.preview(key, locale, body.subject, body.body_text, body.body_html)
