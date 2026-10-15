"""Persistent settings store (key -> JSON). The only code that reads or writes app_settings."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.models.system import AppSetting


class SettingsStore:
    def __init__(self, session: Session, clock: Clock) -> None:
        self._session = session
        self._clock = clock

    def get(self, key: str, default: dict[str, Any] | None = None) -> dict[str, Any] | None:
        row = self._session.get(AppSetting, key)
        return dict(row.value) if row is not None else default

    def put(self, key: str, value: dict[str, Any], updated_by: str = "system") -> None:
        row = self._session.get(AppSetting, key)
        if row is None:
            self._session.add(AppSetting(key=key, value=value, updated_at=self._clock.now(), updated_by=updated_by))
        else:
            row.value = value
            row.updated_at = self._clock.now()
            row.updated_by = updated_by

    def put_if_absent(self, key: str, value: dict[str, Any]) -> bool:
        if self._session.get(AppSetting, key) is not None:
            return False
        self.put(key, value)
        return True
