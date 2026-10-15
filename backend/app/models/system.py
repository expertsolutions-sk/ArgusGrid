"""System tables: settings store and the append-only audit and owner logs."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(96), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str] = mapped_column(String(64), default="system")


class AuditRecord(Base):
    """Append-only, hash-chained audit record (IDN-006, ARG-009)."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_ts", "ts"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_object", "object_type", "object_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    prev_hash: Mapped[str] = mapped_column(String(64))
    record_hash: Mapped[str] = mapped_column(String(64))
    actor_kind: Mapped[str] = mapped_column(String(16))  # user | system | service | anonymous
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor_name: Mapped[str] = mapped_column(String(64), default="")
    actor_role: Mapped[str] = mapped_column(String(64), default="")
    channel: Mapped[str] = mapped_column(String(24))  # ui | api | service | cli | scheduler | dev-loginless
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    session_ref: Mapped[str] = mapped_column(String(16), default="")
    request_id: Mapped[str] = mapped_column(String(48), default="")
    action: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str] = mapped_column(String(48), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    result: Mapped[str] = mapped_column(String(16), default="success")
    reason: Mapped[str] = mapped_column(String(255), default="")
    changes: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)  # {"field": {"old": x, "new": y}}
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class OwnerLogRecord(Base):
    """Append-only log visible only to the Emergency Owner (OWN-008)."""

    __tablename__ = "owner_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    action: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str] = mapped_column(String(48), default="")
    object_id: Mapped[str] = mapped_column(String(64), default="")
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class OwnerAttempt(Base):
    """Failed owner-path attempts, used for the owner's own rate limit (OWN-010)."""

    __tablename__ = "owner_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default="")
