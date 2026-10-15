"""Vulnerability intelligence tables (ARG-016)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class IntelSource(Base):
    __tablename__ = "intel_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(96))
    kind: Mapped[str] = mapped_column(String(16))  # kev | nvd | epss | csaf | bundle | manual
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    url: Mapped[str] = mapped_column(String(512), default="")
    interval_hours: Mapped[int] = mapped_column(Integer, default=6)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(16), default="never")  # never | ok | error
    last_error: Mapped[str] = mapped_column(String(255), default="")
    last_items: Mapped[int] = mapped_column(Integer, default=0)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (Index("ix_vuln_severity", "severity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vuln_id: Mapped[str] = mapped_column(String(64), unique=True)  # CVE-... or DEMO-...
    title: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(12), default="medium")  # low | medium | high | critical
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)  # exploitation known (for example CISA KEV)
    fix_status: Mapped[str] = mapped_column(String(12), default="unknown")  # none | available | workaround | unknown
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # [{"vendor": str, "product": str, "cpe": str, "versions": {"eq": [..], "gte": s, "gt": s, "lte": s, "lt": s}}]
    affected: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    references: Mapped[list[str]] = mapped_column(JSONB, default=list)
    sources: Mapped[list[str]] = mapped_column(JSONB, default=list)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)

    findings: Mapped[list["Finding"]] = relationship(back_populates="vulnerability", cascade="all, delete-orphan")


class Finding(Base):
    """A vulnerability that applies to a managed asset."""

    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "asset_id", name="uq_finding"),
        Index("ix_finding_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"))
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    matched_on: Mapped[str] = mapped_column(String(160), default="")  # software entry or firmware that matched
    match_basis: Mapped[str] = mapped_column(String(16), default="product")  # cpe | product | firmware
    confidence: Mapped[str] = mapped_column(String(8), default="high")  # high | low (version not verifiable)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | acknowledged | mitigated | false_positive
    first_matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str] = mapped_column(String(64), default="")
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str] = mapped_column(String(500), default="")
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="findings", lazy="joined")
