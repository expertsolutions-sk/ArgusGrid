"""Append-only, hash-chained audit log with redaction (IDN-006, ARG-009, OWN-008)."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.context import RequestContext
from app.models.system import AuditRecord, OwnerLogRecord

GENESIS_HASH = "0" * 64
_ADVISORY_LOCK_KEY = 726_001  # serialises appends so the chain stays linear

# Keys whose values are never written (passwords, hashes, tokens, secrets).
SENSITIVE_KEYS = frozenset(
    {
        "password", "new_password", "current_password", "old_password", "confirm_password", "password_hash",
        "hash", "token", "csrf_token", "secret", "temp_password", "api_key", "authorization", "cookie",
        "verifier", "smtp_password", "owner_secret",
    }
)
REDACTED = "[redacted]"


def redact(value: Any) -> Any:
    """Return a copy where every sensitive key is replaced. Applies recursively to dicts and lists."""
    if isinstance(value, dict):
        return {
            k: (REDACTED if str(k).lower() in SENSITIVE_KEYS else redact(v)) for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def diff(old: dict[str, Any] | None, new: dict[str, Any] | None) -> dict[str, Any]:
    """Field-level change set {field: {old, new}} with sensitive fields redacted on both sides."""
    old = old or {}
    new = new or {}
    changes: dict[str, Any] = {}
    for key in sorted(set(old) | set(new)):
        if old.get(key) != new.get(key):
            if key.lower() in SENSITIVE_KEYS:
                changes[key] = {"old": REDACTED, "new": REDACTED}
            else:
                changes[key] = {"old": redact(old.get(key)), "new": redact(new.get(key))}
    return changes


def _canonical(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def _iso(moment: datetime) -> str:
    """Stable timestamp text: always UTC, so the value is identical before and after the database round trip."""
    return moment.astimezone(timezone.utc).isoformat()


class AuditService:
    def __init__(self, session: Session, clock: Clock) -> None:
        self._session = session
        self._clock = clock

    def record(
        self,
        action: str,
        ctx: RequestContext,
        *,
        object_type: str = "",
        object_id: str | int = "",
        result: str = "success",
        reason: str = "",
        changes: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
        actor_override: tuple[str, str] | None = None,
    ) -> AuditRecord:
        """Append one record. The owner appears as "System"; the full entry goes to the owner log (OWN-008)."""
        actor = ctx.actor
        clean_changes = redact(changes or {})
        clean_details = redact(details or {})
        if actor.is_owner:
            self._owner_log(action, ctx, object_type, str(object_id), clean_details)
            actor_kind, actor_name, actor_role, actor_id = "system", "System", "", None
        else:
            actor_kind, actor_name, actor_role, actor_id = actor.kind, actor.name, actor.role, actor.user_id
        if actor_override is not None:
            actor_name, actor_role = actor_override

        self._session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ADVISORY_LOCK_KEY})
        previous = self._session.execute(
            select(AuditRecord.record_hash).order_by(AuditRecord.id.desc()).limit(1)
        ).scalar_one_or_none()
        prev_hash = previous or GENESIS_HASH
        ts = self._clock.now()
        body = {
            "ts": _iso(ts), "actor_kind": actor_kind, "actor_id": actor_id, "actor_name": actor_name,
            "actor_role": actor_role, "channel": ctx.channel, "source_ip": ctx.source_ip, "action": action,
            "object_type": object_type, "object_id": str(object_id), "result": result, "reason": reason,
            "changes": clean_changes, "details": clean_details,
        }
        record_hash = hashlib.sha256((prev_hash + _canonical(body)).encode("utf-8")).hexdigest()
        row = AuditRecord(
            ts=ts, prev_hash=prev_hash, record_hash=record_hash, actor_kind=actor_kind, actor_id=actor_id,
            actor_name=actor_name, actor_role=actor_role, channel=ctx.channel, source_ip=ctx.source_ip,
            user_agent=ctx.user_agent[:255], session_ref=ctx.session_ref, request_id=ctx.request_id,
            action=action, object_type=object_type, object_id=str(object_id), result=result, reason=reason[:255],
            changes=clean_changes, details=clean_details,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def owner_only(self, action: str, ctx: RequestContext, *, details: dict[str, Any] | None = None) -> None:
        """Write to the owner log without any normal audit entry (used for the owner's own login)."""
        self._owner_log(action, ctx, "", "", redact(details or {}))

    def _owner_log(self, action: str, ctx: RequestContext, object_type: str, object_id: str,
                   details: dict[str, Any]) -> None:
        self._session.add(
            OwnerLogRecord(ts=self._clock.now(), action=action, object_type=object_type, object_id=object_id,
                           source_ip=ctx.source_ip, details=details)
        )

    def verify_chain(self) -> bool:
        """Re-compute the hash chain. False means a record was altered or removed."""
        prev = GENESIS_HASH
        rows = self._session.execute(select(AuditRecord).order_by(AuditRecord.id)).scalars()
        for row in rows:
            body = {
                "ts": _iso(row.ts), "actor_kind": row.actor_kind, "actor_id": row.actor_id,
                "actor_name": row.actor_name, "actor_role": row.actor_role, "channel": row.channel,
                "source_ip": row.source_ip, "action": row.action, "object_type": row.object_type,
                "object_id": row.object_id, "result": row.result, "reason": row.reason,
                "changes": row.changes, "details": row.details,
            }
            expected = hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()
            if row.prev_hash != prev or row.record_hash != expected:
                return False
            prev = row.record_hash
        return True
