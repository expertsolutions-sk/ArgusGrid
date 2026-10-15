"""Incident tables: correlated physical and cyber events (ARG-017)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incident_status", "status"), Index("ix_incident_key", "key"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(16), default="")  # HYB-0001, PHY-0002, CYB-0003
    key: Mapped[str] = mapped_column(String(160))  # dedupe key: type|zone|track|asset
    type: Mapped[str] = mapped_column(String(12))  # hybrid | physical | cyber
    severity: Mapped[str] = mapped_column(String(12))  # low | medium | high | critical
    score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="new")  # new|triaged|investigating|contained|closed
    escalated: Mapped[bool] = mapped_column(Boolean, default=False)
    title: Mapped[str] = mapped_column(String(255), default="")
    zone_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    track_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    primary_asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    link_asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    blast_radius: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    recommendations: Mapped[list[str]] = mapped_column(JSONB, default=list)
    assigned_to: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_signal_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    events: Mapped[list["IncidentEvent"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentEvent.id")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    kind: Mapped[str] = mapped_column(String(16))  # created | update | status | note | escalated | notified
    actor: Mapped[str] = mapped_column(String(64), default="system")
    text: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    incident: Mapped[Incident] = relationship(back_populates="events")
