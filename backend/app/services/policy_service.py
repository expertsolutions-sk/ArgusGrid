"""Password policy module (rules/17). The only place that knows policy numbers and character rules (PWD-001)."""
from __future__ import annotations

import secrets
import string
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.errors import invalid
from app.services.settings_store import SettingsStore

SETTING_KEY = "password_policy"

# PWD-004: limits the framework refuses to cross, defined once.
FLOOR_MIN_LENGTH = 6
CEILING_MAX_LENGTH = 128
MAX_HISTORY = 24
MAX_EXPIRY_MONTHS = 60
MAX_MIN_AGE_HOURS = 24 * 90
MAX_REVEAL_SECONDS = 300

_AMBIGUOUS = set("O0oIl1|`'\"")
_LOWER = [c for c in string.ascii_lowercase if c not in _AMBIGUOUS]
_UPPER = [c for c in string.ascii_uppercase if c not in _AMBIGUOUS]
_DIGIT = [c for c in string.digits if c not in _AMBIGUOUS]
_SPECIAL = list("!#$%&*+-=?@^_~")

_COMMON_FILE = Path(__file__).resolve().parents[1] / "data" / "common_passwords.txt"


@lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    try:
        lines = _COMMON_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return frozenset()
    return frozenset(line.strip().lower() for line in lines if line.strip())


@dataclass
class PasswordPolicy:
    min_length: int = 12
    max_length: int = 128
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_special: bool = True
    expiration_enabled: bool = True
    expiration_months: int = 6
    expiry_notice_days: int = 14
    history_count: int = 5
    history_applies_to_admin_set: bool = True
    min_age_hours: int = 48
    reveal_autohide_seconds: int = 5
    reject_username: bool = True
    reject_common: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PasswordPolicy":
        """Build from stored or submitted data. Unknown keys are ignored, missing keys take defaults."""
        base = cls()
        values: dict[str, Any] = {}
        for f in fields(cls):
            if f.name not in data:
                continue
            raw = data[f.name]
            default = getattr(base, f.name)
            if isinstance(default, bool):
                if not isinstance(raw, bool):
                    raise ValueError(f.name)
                values[f.name] = raw
            else:
                if isinstance(raw, bool) or not isinstance(raw, int):
                    raise ValueError(f.name)
                values[f.name] = raw
        return cls(**{**asdict(base), **values})

    @property
    def required_class_count(self) -> int:
        return sum([self.require_upper, self.require_lower, self.require_digit, self.require_special])


def profile_defaults(profile: str) -> PasswordPolicy:
    """Profiles of rules/17 section 1. `custom` values come from the intake and equal `standard` until set."""
    if profile == "minimal":
        return PasswordPolicy(
            min_length=8, require_upper=False, require_lower=False, require_digit=False, require_special=False,
            expiration_enabled=False, history_count=0, min_age_hours=0, reject_username=False, reject_common=False,
        )
    return PasswordPolicy()


def check_consistency(policy: PasswordPolicy) -> list[dict[str, Any]]:
    """PWD-003: return every conflict, each naming the settings involved. Empty list = consistent."""
    problems: list[dict[str, Any]] = []

    def add(code: str, *names: str) -> None:
        problems.append({"code": code, "fields": list(names)})

    if policy.min_length < FLOOR_MIN_LENGTH:
        add("policy.min_length_below_floor", "min_length")
    if policy.max_length > CEILING_MAX_LENGTH:
        add("policy.max_length_above_ceiling", "max_length")
    if policy.min_length > policy.max_length:
        add("policy.min_above_max", "min_length", "max_length")
    if policy.min_length < policy.required_class_count:
        add("policy.min_below_class_count", "min_length", "require_upper", "require_lower", "require_digit",
            "require_special")
    if policy.history_count < 0 or policy.history_count > MAX_HISTORY:
        add("policy.history_out_of_range", "history_count")
    if policy.expiration_enabled and not 1 <= policy.expiration_months <= MAX_EXPIRY_MONTHS:
        add("policy.expiration_out_of_range", "expiration_enabled", "expiration_months")
    if policy.min_age_hours < 0 or policy.min_age_hours > MAX_MIN_AGE_HOURS:
        add("policy.min_age_out_of_range", "min_age_hours")
    if (
        policy.expiration_enabled
        and policy.expiration_months >= 1
        and policy.min_age_hours > policy.expiration_months * 30 * 24
    ):
        add("policy.min_age_above_expiration", "min_age_hours", "expiration_months")
    if policy.expiration_enabled and policy.expiry_notice_days < 0:
        add("policy.notice_negative", "expiry_notice_days")
    if (
        policy.expiration_enabled
        and policy.expiration_months >= 1
        and policy.expiry_notice_days >= policy.expiration_months * 30
    ):
        add("policy.notice_above_expiration", "expiry_notice_days", "expiration_months")
    if not 0 <= policy.reveal_autohide_seconds <= MAX_REVEAL_SECONDS:
        add("policy.reveal_out_of_range", "reveal_autohide_seconds")
    return problems


def add_months(moment: datetime, months: int) -> datetime:
    month_index = moment.month - 1 + months
    year = moment.year + month_index // 12
    month = month_index % 12 + 1
    day = min(moment.day, [31, 29 if year % 4 == 0 and (year % 100 or year % 400 == 0) else 28, 31, 30, 31, 30, 31,
                           31, 30, 31, 30, 31][month - 1])
    return moment.replace(year=year, month=month, day=day)


def evaluate(policy: PasswordPolicy, password: str, username: str = "") -> list[str]:
    """PWD-006: return the codes of ALL failed rules (history and minimum age are checked elsewhere)."""
    failed: list[str] = []
    if len(password) < policy.min_length:
        failed.append("password.too_short")
    if len(password) > policy.max_length:
        failed.append("password.too_long")
    if policy.require_upper and not any(c.isupper() for c in password):
        failed.append("password.no_upper")
    if policy.require_lower and not any(c.islower() for c in password):
        failed.append("password.no_lower")
    if policy.require_digit and not any(c.isdigit() for c in password):
        failed.append("password.no_digit")
    if policy.require_special and not any((not c.isalnum()) and (not c.isspace()) for c in password):
        failed.append("password.no_special")
    if policy.reject_username and username and username.lower() in password.lower():
        failed.append("password.contains_username")
    if policy.reject_common and password.lower() in _common_passwords():
        failed.append("password.common")
    return failed


def generate(policy: PasswordPolicy, username: str = "") -> str:
    """PWD-020: generate from the active policy with a cryptographic generator, then validate it."""
    length = min(max(policy.min_length, 16), policy.max_length)
    rng = secrets.SystemRandom()
    for _ in range(200):
        chars: list[str] = []
        if policy.require_upper:
            chars.append(secrets.choice(_UPPER))
        if policy.require_lower:
            chars.append(secrets.choice(_LOWER))
        if policy.require_digit:
            chars.append(secrets.choice(_DIGIT))
        if policy.require_special:
            chars.append(secrets.choice(_SPECIAL))
        pool = _LOWER + _UPPER + _DIGIT + (_SPECIAL if policy.require_special else [])
        while len(chars) < length:
            chars.append(secrets.choice(pool))
        rng.shuffle(chars)
        candidate = "".join(chars)
        if not evaluate(policy, candidate, username):
            return candidate
    raise RuntimeError("could not generate a password that satisfies the policy")


class PasswordPolicyService:
    """Reads and writes the active policy. Every code path that handles passwords goes through here."""

    def __init__(self, store: SettingsStore) -> None:
        self._store = store

    def get(self) -> PasswordPolicy:
        stored = self._store.get(SETTING_KEY)
        if stored is None:
            return PasswordPolicy()
        try:
            return PasswordPolicy.from_dict(stored)
        except ValueError:
            return PasswordPolicy()

    def update(self, data: dict[str, Any], actor: str) -> PasswordPolicy:
        try:
            policy = PasswordPolicy.from_dict(data)
        except ValueError as exc:
            raise invalid("policy.invalid_value", {"fields": [str(exc)]}) from exc
        problems = check_consistency(policy)
        if problems:
            raise invalid("policy.inconsistent", problems)
        self._store.put(SETTING_KEY, policy.to_dict(), updated_by=actor)
        return policy

    def seed_profile(self, profile: str) -> None:
        self._store.put_if_absent(SETTING_KEY, profile_defaults(profile).to_dict())

    def summary(self) -> dict[str, Any]:
        """What the client needs for the live checklist (PWD-037). The client never hard-codes numbers."""
        p = self.get()
        return {
            "min_length": p.min_length,
            "max_length": p.max_length,
            "require_upper": p.require_upper,
            "require_lower": p.require_lower,
            "require_digit": p.require_digit,
            "require_special": p.require_special,
            "reject_username": p.reject_username,
            "reject_common": p.reject_common,
            "history_count": p.history_count,
            "min_age_hours": p.min_age_hours,
            "reveal_autohide_seconds": p.reveal_autohide_seconds,
        }
