"""Templates, outbox and delivery (ARG-006, ARG-008, ARG-007)."""
from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.crypto import SecretBox
from app.core.errors import ApiError, invalid, not_found
from app.models.identity import User
from app.models.mail import EmailTemplate, EmailTemplateVersion, MailOutbox
from app.services import mail_templates as mt
from app.services.email_settings import EmailSettingsService, SmtpConfig
from app.services.policy_service import PasswordPolicyService

MAX_ATTEMPTS = 5
BACKOFF_MINUTES = (1, 5, 15, 60)
APP_NAME = "ArgusGrid"


# -- transport -----------------------------------------------------------------------------------------
class MailTransport(Protocol):
    def send(self, config: SmtpConfig, message: EmailMessage) -> None: ...


class SmtpTransport:
    """Real delivery through smtplib. Timeouts keep a dead server from blocking the worker."""

    def send(self, config: SmtpConfig, message: EmailMessage) -> None:
        context = ssl.create_default_context()
        if config.tls_mode == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(config.host, config.port, timeout=15, context=context)
        else:
            client = smtplib.SMTP(config.host, config.port, timeout=15)
        with client:
            client.ehlo()
            if config.tls_mode == "starttls":
                client.starttls(context=context)
                client.ehlo()
            if config.username:
                client.login(config.username, config.password)
            client.send_message(message)


class RecordingTransport:
    """Test double: records messages, optionally fails."""

    def __init__(self) -> None:
        self.sent: list[EmailMessage] = []
        self.fail_with: Exception | None = None

    def send(self, config: SmtpConfig, message: EmailMessage) -> None:  # noqa: ARG002
        if self.fail_with is not None:
            raise self.fail_with
        self.sent.append(message)


# -- templates -----------------------------------------------------------------------------------------
@dataclass
class EffectiveTemplate:
    key: str
    locale: str
    subject: str
    body_text: str
    body_html: str
    version: int
    customized: bool


class TemplateService:
    def __init__(self, session: Session, clock: Clock) -> None:
        self._session = session
        self._clock = clock

    def _row(self, key: str, locale: str) -> EmailTemplate | None:
        return self._session.execute(
            select(EmailTemplate).where(EmailTemplate.key == key, EmailTemplate.locale == locale)
        ).scalar_one_or_none()

    def effective(self, key: str, locale: str) -> EffectiveTemplate:
        if key not in mt.SPECS:
            raise not_found("email.template_unknown")
        if locale not in mt.LOCALES:
            locale = mt.DEFAULT_LOCALE
        row = self._row(key, locale)
        if row is not None:
            return EffectiveTemplate(key, locale, row.subject, row.body_text, row.body_html, row.version, True)
        subject, text = mt.default_for(key, locale)
        return EffectiveTemplate(key, locale, subject, text, "", 0, False)

    def catalogue(self) -> list[dict[str, Any]]:
        rows = self._session.execute(select(EmailTemplate.key, EmailTemplate.locale)).all()
        custom = {(k, l) for k, l in rows}
        return [
            {
                "key": spec.key, "title": spec.title, "variables": list(spec.variables), "sensitive": spec.sensitive,
                "locales": [{"locale": loc, "customized": (spec.key, loc) in custom} for loc in mt.LOCALES],
            }
            for spec in mt.CATALOGUE
        ]

    def update(self, key: str, locale: str, subject: str, body_text: str, body_html: str, actor: str) -> EffectiveTemplate:
        if locale not in mt.LOCALES:
            raise invalid("email.locale_invalid")
        try:
            mt.validate(key, subject, body_text, body_html)
        except mt.TemplateProblem as problem:
            raise invalid("email.template_invalid", [{"code": problem.code, "fields": problem.names}]) from problem
        now = self._clock.now()
        row = self._row(key, locale)
        if row is None:
            row = EmailTemplate(key=key, locale=locale, subject=subject, body_text=body_text, body_html=body_html,
                                version=1, updated_at=now, updated_by=actor)
            self._session.add(row)
        else:
            row.subject, row.body_text, row.body_html = subject, body_text, body_html
            row.version += 1
            row.updated_at, row.updated_by = now, actor
        self._session.add(EmailTemplateVersion(
            key=key, locale=locale, version=row.version, subject=subject, body_text=body_text,
            body_html=body_html, changed_at=now, changed_by=actor))
        self._session.flush()
        return self.effective(key, locale)

    def reset(self, key: str, locale: str) -> None:
        row = self._row(key, locale)
        if row is not None:
            self._session.delete(row)

    def versions(self, key: str, locale: str) -> list[dict[str, Any]]:
        rows = self._session.execute(
            select(EmailTemplateVersion)
            .where(EmailTemplateVersion.key == key, EmailTemplateVersion.locale == locale)
            .order_by(EmailTemplateVersion.version.desc())
        ).scalars()
        return [{"version": r.version, "changed_at": r.changed_at.isoformat(), "changed_by": r.changed_by,
                 "subject": r.subject} for r in rows]

    def preview(self, key: str, locale: str, subject: str, body_text: str, body_html: str) -> dict[str, str]:
        try:
            mt.validate(key, subject, body_text, body_html)
            rendered = mt.render(subject, body_text, body_html, mt.SAMPLE)
        except mt.TemplateProblem as problem:
            raise invalid("email.template_invalid", [{"code": problem.code, "fields": problem.names}]) from problem
        return {"subject": rendered[0], "text": rendered[1], "html": rendered[2]}


# -- outbox and delivery -------------------------------------------------------------------------------
@dataclass
class SendReport:
    sent: int = 0
    failed: int = 0
    retry: int = 0
    waiting: int = 0  # not sent because e-mail is switched off or not configured


class MailService:
    def __init__(self, session: Session, clock: Clock, templates: TemplateService, settings: EmailSettingsService,
                 box: SecretBox) -> None:
        self._session = session
        self._clock = clock
        self._templates = templates
        self._settings = settings
        self._box = box

    # -- queueing ---------------------------------------------------------------------------------
    def queue(self, key: str, user: User, variables: dict[str, Any], *, to: str | None = None) -> MailOutbox | None:
        """Render and queue one message for a user. Returns None when the user has no address."""
        address = (to or user.email or "").strip()
        if not address:
            return None
        spec = mt.SPECS[key]
        config = self._settings.get_config()
        full = {
            "app_name": APP_NAME, "username": user.username, "full_name": user.full_name,
            "login_url": config.login_url, **variables,
        }
        template = self._templates.effective(key, user.locale)
        try:
            subject, text, html = mt.render(template.subject, template.body_text, template.body_html, full)
        except mt.TemplateProblem:
            # a saved custom template that fails to render must never block a security mail: use the default
            d_subject, d_text = mt.default_for(key, template.locale)
            subject, text, html = mt.render(d_subject, d_text, "", full)
        row = MailOutbox(
            created_at=self._clock.now(), template_key=key, locale=template.locale, to_address=address,
            subject=subject, sensitive=spec.sensitive, status="pending", next_attempt_at=self._clock.now(),
            related_user_id=user.id,
        )
        if spec.sensitive:  # credentials are stored encrypted until sent (ARG-006)
            row.body_text = self._box.encrypt(text)
            row.body_html = self._box.encrypt(html)
        else:
            row.body_text, row.body_html = text, html
        self._session.add(row)
        self._session.flush()
        return row

    def configured(self) -> bool:
        c = self._settings.get_config()
        return c.enabled and bool(c.host) and bool(c.from_address)

    # -- delivery ---------------------------------------------------------------------------------
    def send_pending(self, transport: MailTransport, limit: int = 25) -> SendReport:
        report = SendReport()
        config = self._settings.get_config()
        now = self._clock.now()
        rows = list(self._session.execute(
            select(MailOutbox)
            .where(MailOutbox.status == "pending", (MailOutbox.next_attempt_at.is_(None)) | (MailOutbox.next_attempt_at <= now))
            .order_by(MailOutbox.id).limit(limit)
        ).scalars())
        if not (config.enabled and config.host and config.from_address):
            report.waiting = len(rows)
            return report
        for row in rows:
            try:
                transport.send(config, self._build(config, row))
            except Exception as exc:  # delivery errors must never crash the worker
                row.attempts += 1
                row.last_error = f"{type(exc).__name__}: {exc}"[:255]
                if row.attempts >= MAX_ATTEMPTS:
                    row.status = "failed"
                    report.failed += 1
                else:
                    delay = BACKOFF_MINUTES[min(row.attempts - 1, len(BACKOFF_MINUTES) - 1)]
                    row.next_attempt_at = now + timedelta(minutes=delay)
                    report.retry += 1
                continue
            row.status = "sent"
            row.sent_at = now
            row.attempts += 1
            row.last_error = ""
            row.body_text = ""  # wipe: nothing readable stays in the outbox after sending
            row.body_html = ""
            report.sent += 1
        return report

    def _build(self, config: SmtpConfig, row: MailOutbox) -> EmailMessage:
        text, html = row.body_text, row.body_html
        if row.sensitive:
            text = self._box.decrypt(text) or ""
            html = self._box.decrypt(html) or ""
            if not text:
                raise ApiError(500, "outbox_unreadable")
        message = EmailMessage()
        message["Subject"] = row.subject
        message["From"] = formataddr((config.from_name, config.from_address))
        message["To"] = row.to_address
        message["Message-ID"] = make_msgid(domain=config.from_address.split("@")[-1])
        message.set_content(text)
        if html:
            message.add_alternative(html, subtype="html")
        return message

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._session.execute(select(MailOutbox).order_by(MailOutbox.id.desc()).limit(limit)).scalars()
        return [
            {"id": r.id, "created_at": r.created_at.isoformat(), "template": r.template_key, "to": r.to_address,
             "subject": r.subject, "status": r.status, "attempts": r.attempts, "error": r.last_error,
             "sent_at": r.sent_at.isoformat() if r.sent_at else None}
            for r in rows
        ]


# -- password expiry notification ----------------------------------------------------------------------
class ExpiryNotifier:
    """Queues `password.expiring` once per expiry date, N days before (N from the password policy)."""

    def __init__(self, session: Session, clock: Clock, policy: PasswordPolicyService, mail: MailService) -> None:
        self._session = session
        self._clock = clock
        self._policy = policy
        self._mail = mail

    def run(self) -> int:
        policy = self._policy.get()
        if not policy.expiration_enabled:
            return 0
        now = self._clock.now()
        horizon = now + timedelta(days=policy.expiry_notice_days)
        users = self._session.execute(
            select(User).where(
                User.is_active.is_(True), User.is_service.is_(False), User.password_expires_at.is_not(None),
                User.password_expires_at <= horizon, User.password_expires_at > now,
            )
        ).scalars()
        queued = 0
        for user in users:
            if user.expiry_notified_for == user.password_expires_at:
                continue
            expires = user.password_expires_at
            assert expires is not None
            days_left = max(0, (expires - now).days)
            row = self._mail.queue(
                "password.expiring", user, {"expires_at": expires.date().isoformat(), "days_left": days_left}
            )
            user.expiry_notified_for = expires  # also when there is no address, so it is not retried forever
            if row is not None:
                queued += 1
        return queued
