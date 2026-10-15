"""Server-side sessions (IDN-003, rules/03). Only the digest of the token is stored."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.context import RequestContext
from app.core.errors import invalid
from app.core.security import new_token, token_digest
from app.models.identity import SessionRecord
from app.services.settings_store import SettingsStore

SETTING_KEY = "session_policy"


@dataclass
class SessionPolicy:
    inactivity_minutes: int = 30
    absolute_hours: int = 12

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SessionPolicyService:
    def __init__(self, store: SettingsStore) -> None:
        self._store = store

    def get(self) -> SessionPolicy:
        stored = self._store.get(SETTING_KEY) or {}
        base = SessionPolicy()
        try:
            return SessionPolicy(
                inactivity_minutes=int(stored.get("inactivity_minutes", base.inactivity_minutes)),
                absolute_hours=int(stored.get("absolute_hours", base.absolute_hours)),
            )
        except (TypeError, ValueError):
            return base

    def update(self, data: dict[str, Any], actor: str) -> SessionPolicy:
        try:
            policy = SessionPolicy(
                inactivity_minutes=int(data["inactivity_minutes"]), absolute_hours=int(data["absolute_hours"])
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise invalid("session.invalid_value") from exc
        problems: list[dict[str, Any]] = []
        if not 1 <= policy.inactivity_minutes <= 24 * 60:
            problems.append({"code": "session.inactivity_out_of_range", "fields": ["inactivity_minutes"]})
        if not 1 <= policy.absolute_hours <= 24 * 30:
            problems.append({"code": "session.absolute_out_of_range", "fields": ["absolute_hours"]})
        if not problems and policy.inactivity_minutes > policy.absolute_hours * 60:
            problems.append(
                {"code": "session.inactivity_above_absolute", "fields": ["inactivity_minutes", "absolute_hours"]}
            )
        if problems:
            raise invalid("session.inconsistent", problems)
        self._store.put(SETTING_KEY, policy.to_dict(), updated_by=actor)
        return policy

    def seed_defaults(self) -> None:
        self._store.put_if_absent(SETTING_KEY, SessionPolicy().to_dict())


class SessionService:
    def __init__(self, db_session: Session, clock: Clock, policy: SessionPolicyService) -> None:
        self._session = db_session
        self._clock = clock
        self._policy = policy

    def create(self, ctx: RequestContext, *, user_id: int | None, is_owner: bool = False) -> tuple[str, SessionRecord]:
        now = self._clock.now()
        policy = self._policy.get()
        token = new_token(32)
        row = SessionRecord(
            token_digest=token_digest(token),
            user_id=user_id,
            is_owner=is_owner,
            csrf_token=new_token(24),
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(hours=policy.absolute_hours),
            source_ip=ctx.source_ip,
            user_agent=ctx.user_agent[:255],
        )
        self._session.add(row)
        self._session.flush()
        return token, row

    def resolve(self, token: str | None) -> SessionRecord | None:
        """Return the live session for a token, or None when unknown, revoked or expired."""
        if not token:
            return None
        row = self._session.execute(
            select(SessionRecord).where(SessionRecord.token_digest == token_digest(token))
        ).scalar_one_or_none()
        if row is None or row.revoked_at is not None:
            return None
        now = self._clock.now()
        policy = self._policy.get()
        if now >= row.expires_at or now - row.last_seen_at > timedelta(minutes=policy.inactivity_minutes):
            row.revoked_at = now
            return None
        row.last_seen_at = now
        return row

    def revoke(self, row: SessionRecord) -> None:
        row.revoked_at = self._clock.now()

    def revoke_user_sessions(self, user_id: int, *, except_id: int | None = None) -> None:
        stmt = update(SessionRecord).where(SessionRecord.user_id == user_id, SessionRecord.revoked_at.is_(None))
        if except_id is not None:
            stmt = stmt.where(SessionRecord.id != except_id)
        self._session.execute(stmt.values(revoked_at=self._clock.now()))
