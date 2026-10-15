"""Lockout policy model, defaults and consistency validation (rules/18)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from app.core.errors import invalid
from app.core.permissions import ADMINISTRATOR
from app.services.settings_store import SettingsStore

SETTING_KEY = "lockout_policy"

MODES = ("auto_unlock", "permanent", "escalating")
AFTER_UNLOCK = ("none", "require_password_change", "reset_password")


@dataclass
class LockoutPolicy:
    threshold: int = 5
    window_minutes: int = 15
    mode: str = "auto_unlock"
    durations_minutes: list[int] = field(default_factory=lambda: [15])
    cycles_before_permanent: int | None = 3
    unlockers: list[str] = field(default_factory=lambda: [ADMINISTRATOR])
    after_unlock: str = "none"
    revoke_sessions: bool = True
    notify: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LockoutPolicy":
        base = cls()
        durations = data.get("durations_minutes", base.durations_minutes)
        if not isinstance(durations, list) or not all(isinstance(d, int) and not isinstance(d, bool) for d in durations):
            raise ValueError("durations_minutes")
        cycles = data.get("cycles_before_permanent", base.cycles_before_permanent)
        if cycles is not None and (isinstance(cycles, bool) or not isinstance(cycles, int)):
            raise ValueError("cycles_before_permanent")
        unlockers = data.get("unlockers", base.unlockers)
        if not isinstance(unlockers, list) or not all(isinstance(u, str) for u in unlockers):
            raise ValueError("unlockers")
        for name in ("threshold", "window_minutes"):
            value = data.get(name, getattr(base, name))
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(name)
        for name in ("revoke_sessions", "notify"):
            if not isinstance(data.get(name, getattr(base, name)), bool):
                raise ValueError(name)
        mode = data.get("mode", base.mode)
        after = data.get("after_unlock", base.after_unlock)
        if not isinstance(mode, str) or not isinstance(after, str):
            raise ValueError("mode")
        return cls(
            threshold=data.get("threshold", base.threshold),
            window_minutes=data.get("window_minutes", base.window_minutes),
            mode=mode,
            durations_minutes=list(durations),
            cycles_before_permanent=cycles,
            unlockers=list(unlockers),
            after_unlock=after,
            revoke_sessions=data.get("revoke_sessions", base.revoke_sessions),
            notify=data.get("notify", base.notify),
        )


def administrator_defaults() -> LockoutPolicy:
    """D-02: short escalating delay, immediate unlock by another administrator, no long waits."""
    return LockoutPolicy(
        threshold=5, window_minutes=15, mode="escalating", durations_minutes=[1, 2, 5, 10, 15],
        cycles_before_permanent=None, unlockers=[ADMINISTRATOR], after_unlock="require_password_change",
    )


@dataclass
class LockoutSettings:
    exempt_last_administrator: bool = False
    source_throttle_per_minute: int = 20
    default: LockoutPolicy = field(default_factory=LockoutPolicy)
    roles: dict[str, LockoutPolicy] = field(default_factory=lambda: {ADMINISTRATOR: administrator_defaults()})

    def policy_for(self, role_name: str) -> LockoutPolicy:
        return self.roles.get(role_name, self.default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exempt_last_administrator": self.exempt_last_administrator,
            "source_throttle_per_minute": self.source_throttle_per_minute,
            "default": asdict(self.default),
            "roles": {name: asdict(p) for name, p in self.roles.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LockoutSettings":
        exempt = data.get("exempt_last_administrator", False)
        throttle = data.get("source_throttle_per_minute", 20)
        if not isinstance(exempt, bool):
            raise ValueError("exempt_last_administrator")
        if isinstance(throttle, bool) or not isinstance(throttle, int):
            raise ValueError("source_throttle_per_minute")
        default_raw = data.get("default", {})
        roles_raw = data.get("roles", {})
        if not isinstance(default_raw, dict) or not isinstance(roles_raw, dict):
            raise ValueError("roles")
        roles = {str(name): LockoutPolicy.from_dict(raw) for name, raw in roles_raw.items()}
        return cls(
            exempt_last_administrator=exempt,
            source_throttle_per_minute=throttle,
            default=LockoutPolicy.from_dict(default_raw),
            roles=roles,
        )


def check_consistency(settings: LockoutSettings, role_levels: dict[str, int]) -> list[dict[str, Any]]:
    """LCK-001 to LCK-007 (LCK-006 needs the two-factor module, which is off). Returns all conflicts."""
    problems: list[dict[str, Any]] = []

    def add(code: str, scope: str, *names: str) -> None:
        problems.append({"code": code, "scope": scope, "fields": list(names)})

    named: list[tuple[str, LockoutPolicy]] = [("default", settings.default)]
    named += [(name, p) for name, p in settings.roles.items()]

    for scope, p in named:
        if p.mode not in MODES:
            add("lockout.mode_invalid", scope, "mode")
        if p.after_unlock not in AFTER_UNLOCK:
            add("lockout.after_unlock_invalid", scope, "after_unlock")
        if p.threshold < 1 or p.window_minutes < 1:  # LCK-003
            add("lockout.threshold_or_window_invalid", scope, "threshold", "window_minutes")
        if not p.unlockers:  # LCK-002
            add("lockout.no_unlocker", scope, "unlockers")
        if p.cycles_before_permanent is not None and p.cycles_before_permanent < 1:
            add("lockout.cycles_invalid", scope, "cycles_before_permanent")
        if p.mode in ("auto_unlock", "escalating"):
            if not p.durations_minutes or any(d < 1 for d in p.durations_minutes):
                add("lockout.duration_invalid", scope, "durations_minutes")
        if p.mode == "escalating" and p.durations_minutes:
            increasing = all(b > a for a, b in zip(p.durations_minutes, p.durations_minutes[1:]))
            if not increasing:  # LCK-004
                add("lockout.sequence_not_increasing", scope, "durations_minutes")
        if p.mode == "permanent" and scope == ADMINISTRATOR and ADMINISTRATOR not in p.unlockers:  # LCK-001
            add("lockout.permanent_without_unlock_path", scope, "mode", "unlockers")
        # LCK-005: an unlocker must not be lower than the role it unlocks.
        if scope == "default":
            covered = [lvl for name, lvl in role_levels.items() if name not in settings.roles]
            target_level = max(covered) if covered else 0
        else:
            target_level = role_levels.get(scope, 0)
        for unlocker in p.unlockers:
            if role_levels.get(unlocker, 0) < target_level:
                add("lockout.unlocker_below_target", scope, "unlockers")
                break

    if settings.source_throttle_per_minute < 0:
        add("lockout.throttle_invalid", "global", "source_throttle_per_minute")
    if settings.exempt_last_administrator and settings.source_throttle_per_minute == 0:  # LCK-007
        add("lockout.exempt_without_throttle", "global", "exempt_last_administrator", "source_throttle_per_minute")
    return problems


class LockoutSettingsService:
    def __init__(self, store: SettingsStore) -> None:
        self._store = store

    def get(self) -> LockoutSettings:
        stored = self._store.get(SETTING_KEY)
        if stored is None:
            return LockoutSettings()
        try:
            return LockoutSettings.from_dict(stored)
        except ValueError:
            return LockoutSettings()

    def update(self, data: dict[str, Any], role_levels: dict[str, int], actor: str) -> LockoutSettings:
        try:
            settings = LockoutSettings.from_dict(data)
        except ValueError as exc:
            raise invalid("lockout.invalid_value", {"fields": [str(exc)]}) from exc
        problems = check_consistency(settings, role_levels)
        if problems:
            raise invalid("lockout.inconsistent", problems)
        self._store.put(SETTING_KEY, settings.to_dict(), updated_by=actor)
        return settings

    def seed_defaults(self) -> None:
        self._store.put_if_absent(SETTING_KEY, LockoutSettings().to_dict())
