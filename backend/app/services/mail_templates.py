"""E-mail template catalogue, defaults, rendering and validation (ARG-008).

Templates are Jinja2 text rendered in a sandbox with a whitelist of variables per template.
The variable `temp_password` exists only in the credential templates (rules: never stored after sending).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from jinja2 import TemplateError, TemplateSyntaxError, meta
from jinja2.sandbox import SandboxedEnvironment

LOCALES = ("en", "sk")
DEFAULT_LOCALE = "en"

_BASE = ("app_name", "username", "full_name", "login_url")


@dataclass(frozen=True)
class TemplateSpec:
    key: str
    title: str
    variables: tuple[str, ...]
    sensitive: bool = False


CATALOGUE: tuple[TemplateSpec, ...] = (
    TemplateSpec("user.created", "User created", _BASE + ("temp_password", "role_name"), sensitive=True),
    TemplateSpec("user.password_reset", "Password reset", _BASE + ("temp_password",), sensitive=True),
    TemplateSpec("user.unlocked", "Account unlocked", _BASE + ("temp_password",), sensitive=True),
    TemplateSpec("user.password_changed", "Password changed", _BASE + ("changed_at",)),
    TemplateSpec("user.locked", "Account locked", _BASE + ("lock_description",)),
    TemplateSpec("admin.user_locked", "Account locked (notice to administrators)",
                 _BASE + ("locked_username", "lock_description")),
    TemplateSpec("password.expiring", "Password expiring", _BASE + ("expires_at", "days_left")),
    TemplateSpec(
        "alert.critical", "Critical vulnerability alert",
        _BASE + ("vulnerability_id", "title", "classification", "severity", "assets", "detected_at"),
    ),
    TemplateSpec("incident.hybrid", "Hybrid incident",
                 _BASE + ("incident_id", "severity", "zone", "summary", "detected_at")),
    TemplateSpec("system.test", "Test message", _BASE),
)
SPECS = {s.key: s for s in CATALOGUE}

SAMPLE: dict[str, str] = {
    "app_name": "ArgusGrid", "username": "jana.novakova", "full_name": "Jana Nováková",
    "login_url": "https://argusgrid.example/login", "temp_password": "Preview-Only-Pw1!", "role_name": "SOC Analyst",
    "changed_at": "2026-10-12 09:30 UTC", "lock_description": "until 2026-10-12 10:15 UTC",
    "locked_username": "petr.horvath", "expires_at": "2027-04-12", "days_left": "7", "vulnerability_id": "DEMO-2026-0001",
    "title": "Remote code execution in the SCADA web component (demo)", "classification": "zero-hour",
    "severity": "critical", "assets": "SCADA-SRV-01, HMI-03", "detected_at": "2026-10-12 09:30 UTC",
    "incident_id": "HYB-0001", "zone": "Z2 Control and SCADA core", "summary": "UAV loitering near WIFI-AP-MNT",
}

# (subject, text body) per key and locale. HTML is derived from the text unless a custom HTML body is saved.
_D: dict[str, dict[str, tuple[str, str]]] = {
    "user.created": {
        "en": ("Your {{ app_name }} account",
               "Hello {{ full_name or username }},\n\nAn account was created for you in {{ app_name }}.\n\n"
               "User name: {{ username }}\nRole: {{ role_name }}\nTemporary password: {{ temp_password }}\n\n"
               "Sign in at {{ login_url }}. You must choose a new password at your first sign-in.\n"),
        "sk": ("Váš účet v {{ app_name }}",
               "Dobrý deň {{ full_name or username }},\n\nBol vám vytvorený účet v systéme {{ app_name }}.\n\n"
               "Používateľské meno: {{ username }}\nRola: {{ role_name }}\nDočasné heslo: {{ temp_password }}\n\n"
               "Prihláste sa na {{ login_url }}. Pri prvom prihlásení musíte zvoliť nové heslo.\n"),
    },
    "user.password_reset": {
        "en": ("Your {{ app_name }} password was reset",
               "Hello {{ full_name or username }},\n\nAn administrator reset your password.\n\n"
               "User name: {{ username }}\nTemporary password: {{ temp_password }}\n\n"
               "Sign in at {{ login_url }}. You must choose a new password at your next sign-in.\n"),
        "sk": ("Vaše heslo v {{ app_name }} bolo obnovené",
               "Dobrý deň {{ full_name or username }},\n\nAdministrátor obnovil vaše heslo.\n\n"
               "Používateľské meno: {{ username }}\nDočasné heslo: {{ temp_password }}\n\n"
               "Prihláste sa na {{ login_url }}. Pri najbližšom prihlásení musíte zvoliť nové heslo.\n"),
    },
    "user.unlocked": {
        "en": ("Your {{ app_name }} account was unlocked",
               "Hello {{ full_name or username }},\n\nYour account was unlocked.\n"
               "{% if temp_password %}A new temporary password was set: {{ temp_password }}\n"
               "You must choose a new password at your next sign-in.\n{% endif %}\nSign in at {{ login_url }}.\n"),
        "sk": ("Váš účet v {{ app_name }} bol odomknutý",
               "Dobrý deň {{ full_name or username }},\n\nVáš účet bol odomknutý.\n"
               "{% if temp_password %}Bolo nastavené nové dočasné heslo: {{ temp_password }}\n"
               "Pri najbližšom prihlásení musíte zvoliť nové heslo.\n{% endif %}\nPrihláste sa na {{ login_url }}.\n"),
    },
    "user.password_changed": {
        "en": ("Your {{ app_name }} password was changed",
               "Hello {{ full_name or username }},\n\nYour password was changed on {{ changed_at }}.\n"
               "If this was not you, contact your administrator immediately.\n"),
        "sk": ("Vaše heslo v {{ app_name }} bolo zmenené",
               "Dobrý deň {{ full_name or username }},\n\nVaše heslo bolo zmenené {{ changed_at }}.\n"
               "Ak ste to neboli vy, ihneď kontaktujte administrátora.\n"),
    },
    "user.locked": {
        "en": ("Your {{ app_name }} account was locked",
               "Hello {{ full_name or username }},\n\nYour account was locked ({{ lock_description }}).\n"
               "Repeated failed sign-in attempts cause a lock. Contact your administrator if you need help.\n"),
        "sk": ("Váš účet v {{ app_name }} bol zamknutý",
               "Dobrý deň {{ full_name or username }},\n\nVáš účet bol zamknutý ({{ lock_description }}).\n"
               "Zámok spôsobujú opakované neúspešné pokusy o prihlásenie. V prípade potreby kontaktujte administrátora.\n"),
    },
    "admin.user_locked": {
        "en": ("{{ app_name }}: account {{ locked_username }} was locked",
               "Hello {{ full_name or username }},\n\nThe account {{ locked_username }} was locked "
               "({{ lock_description }}). You can unlock it in {{ app_name }} at {{ login_url }}.\n"),
        "sk": ("{{ app_name }}: účet {{ locked_username }} bol zamknutý",
               "Dobrý deň {{ full_name or username }},\n\nÚčet {{ locked_username }} bol zamknutý "
               "({{ lock_description }}). Môžete ho odomknúť v systéme {{ app_name }} na {{ login_url }}.\n"),
    },
    "password.expiring": {
        "en": ("Your {{ app_name }} password expires in {{ days_left }} days",
               "Hello {{ full_name or username }},\n\nYour password expires on {{ expires_at }} "
               "({{ days_left }} days). Change it before then at {{ login_url }}.\n"),
        "sk": ("Vaše heslo v {{ app_name }} vyprší o {{ days_left }} dní",
               "Dobrý deň {{ full_name or username }},\n\nVaše heslo vyprší {{ expires_at }} "
               "(o {{ days_left }} dní). Zmeňte ho do tohto dátumu na {{ login_url }}.\n"),
    },
    "alert.critical": {
        "en": ("[{{ severity|upper }}] {{ classification }} vulnerability {{ vulnerability_id }}",
               "A {{ classification }} vulnerability affects managed assets.\n\n"
               "Identifier: {{ vulnerability_id }}\nTitle: {{ title }}\nSeverity: {{ severity }}\n"
               "Affected assets: {{ assets }}\nDetected: {{ detected_at }}\n\nOpen {{ login_url }} for details.\n"),
        "sk": ("[{{ severity|upper }}] zraniteľnosť {{ classification }} {{ vulnerability_id }}",
               "Zraniteľnosť typu {{ classification }} sa týka spravovaných aktív.\n\n"
               "Identifikátor: {{ vulnerability_id }}\nNázov: {{ title }}\nZávažnosť: {{ severity }}\n"
               "Dotknuté aktíva: {{ assets }}\nZistené: {{ detected_at }}\n\nPodrobnosti na {{ login_url }}.\n"),
    },
    "incident.hybrid": {
        "en": ("Hybrid incident {{ incident_id }} ({{ severity }})",
               "A hybrid incident was raised.\n\nIncident: {{ incident_id }}\nSeverity: {{ severity }}\n"
               "Zone: {{ zone }}\nSummary: {{ summary }}\nDetected: {{ detected_at }}\n\nOpen {{ login_url }}.\n"),
        "sk": ("Hybridný incident {{ incident_id }} ({{ severity }})",
               "Bol vyhlásený hybridný incident.\n\nIncident: {{ incident_id }}\nZávažnosť: {{ severity }}\n"
               "Zóna: {{ zone }}\nPopis: {{ summary }}\nZistené: {{ detected_at }}\n\nOtvorte {{ login_url }}.\n"),
    },
    "system.test": {
        "en": ("{{ app_name }} test message",
               "This is a test message from {{ app_name }}. E-mail delivery works.\n"),
        "sk": ("Testovacia správa z {{ app_name }}",
               "Toto je testovacia správa z {{ app_name }}. Doručovanie e-mailov funguje.\n"),
    },
}

_env = SandboxedEnvironment(autoescape=False, trim_blocks=True, lstrip_blocks=True)
_html_env = SandboxedEnvironment(autoescape=True, trim_blocks=True, lstrip_blocks=True)


class TemplateProblem(Exception):
    """A template that cannot be saved. `code` is a catalogue key, `names` the offending names."""

    def __init__(self, code: str, names: list[str] | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.names = names or []


def default_for(key: str, locale: str) -> tuple[str, str]:
    by_locale = _D[key]
    return by_locale.get(locale) or by_locale[DEFAULT_LOCALE]


def used_variables(*texts: str) -> set[str]:
    names: set[str] = set()
    for text in texts:
        try:
            names |= meta.find_undeclared_variables(_env.parse(text))
        except TemplateSyntaxError as exc:
            raise TemplateProblem("email.template_syntax", [str(exc.lineno or "")]) from exc
    return names


def validate(key: str, subject: str, body_text: str, body_html: str) -> None:
    spec = SPECS.get(key)
    if spec is None:
        raise TemplateProblem("email.template_unknown", [key])
    if not subject.strip() or not body_text.strip():
        raise TemplateProblem("email.template_empty")
    if len(subject) > 255 or len(body_text) > 20000 or len(body_html) > 40000:
        raise TemplateProblem("email.template_too_long")
    unknown = sorted(used_variables(subject, body_text, body_html) - set(spec.variables))
    if unknown:
        raise TemplateProblem("email.template_unknown_variable", unknown)
    render(subject, body_text, body_html, SAMPLE)  # a template that cannot render is not saved


def _text_to_html(rendered_text: str) -> str:
    from html import escape

    paragraphs = [p for p in rendered_text.strip().split("\n\n") if p.strip()]
    return "".join("<p>" + escape(p).replace("\n", "<br>") + "</p>" for p in paragraphs)


def render(subject: str, body_text: str, body_html: str, variables: dict[str, Any]) -> tuple[str, str, str]:
    """Render subject, plain text and HTML. Missing variables render as empty text."""
    ctx = {k: ("" if v is None else str(v)) for k, v in variables.items()}
    try:
        rendered_subject = _env.from_string(subject).render(**ctx).replace("\n", " ").strip()
        rendered_text = _env.from_string(body_text).render(**ctx)
        if body_html.strip():
            rendered_html = _html_env.from_string(body_html).render(**ctx)
        else:
            rendered_html = _text_to_html(rendered_text)
    except TemplateError as exc:  # includes the sandbox SecurityError: no internals leak, never a 500
        raise TemplateProblem("email.template_unsafe_or_broken") from exc
    return rendered_subject, rendered_text, rendered_html
