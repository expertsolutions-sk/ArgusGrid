"""Asset registry tables (ARG-012) and device credentials (ARG-013)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base


class Zone(Base):
    """A sector of the protected site, used by the correlation engine (physical context)."""

    __tablename__ = "zones"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(16), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    criticality: Mapped[str] = mapped_column(String(12), default="medium")
    polygon: Mapped[list[list[float]]] = mapped_column(JSONB, default=list)  # [[x, y], ...] in site metres
    description: Mapped[str] = mapped_column(String(255), default="")
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (Index("ix_assets_type", "asset_type"), Index("ix_assets_zone", "zone_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(48), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    asset_type: Mapped[str] = mapped_column(String(24))
    category: Mapped[str] = mapped_column(String(16))  # device | comm_node | endpoint
    purdue_level: Mapped[str] = mapped_column(String(4), default="")
    zone_id: Mapped[int | None] = mapped_column(ForeignKey("zones.id", ondelete="SET NULL"), nullable=True)
    location: Mapped[str] = mapped_column(String(128), default="")  # building or room
    x: Mapped[float | None] = mapped_column(Float, nullable=True)
    y: Mapped[float | None] = mapped_column(Float, nullable=True)
    criticality: Mapped[str] = mapped_column(String(12), default="medium")
    status: Mapped[str] = mapped_column(String(16), default="active")
    exposure: Mapped[list[str]] = mapped_column(JSONB, default=list)
    vendor: Mapped[str] = mapped_column(String(64), default="")
    model: Mapped[str] = mapped_column(String(64), default="")
    firmware_version: Mapped[str] = mapped_column(String(48), default="")
    ip_address: Mapped[str] = mapped_column(String(45), default="")
    mac_address: Mapped[str] = mapped_column(String(17), default="")
    protocols: Mapped[list[str]] = mapped_column(JSONB, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    zone: Mapped[Zone | None] = relationship(lazy="joined")
    software: Mapped[list["AssetSoftware"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin", order_by="AssetSoftware.name"
    )


class AssetSoftware(Base):
    """Software inventory entry. The vulnerability matcher of a later slice joins on these."""

    __tablename__ = "asset_software"
    __table_args__ = (UniqueConstraint("asset_id", "name", "version", name="uq_asset_software"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(96))
    vendor: Mapped[str] = mapped_column(String(64), default="")
    version: Mapped[str] = mapped_column(String(48), default="")
    cpe: Mapped[str] = mapped_column(String(255), default="")

    asset: Mapped[Asset] = relationship(back_populates="software")


class AssetRelation(Base):
    """A directed logical dependency between two assets (edge of the topology graph)."""

    __tablename__ = "asset_relations"
    __table_args__ = (UniqueConstraint("source_id", "target_id", "relation", name="uq_asset_relation"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    target_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    relation: Mapped[str] = mapped_column(String(32))
    protocol: Mapped[str] = mapped_column(String(48), default="")
    note: Mapped[str] = mapped_column(String(255), default="")


class DeviceCredential(Base):
    """Per-device key used to sign requests. The secret is stored encrypted (it must be usable for HMAC)."""

    __tablename__ = "device_credentials"
    __table_args__ = (Index("ix_device_credentials_asset", "asset_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    key_id: Mapped[str] = mapped_column(String(32), unique=True)
    secret_enc: Mapped[str] = mapped_column(Text)
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list)
    allowed_networks: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(64), default="system")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_ip: Mapped[str] = mapped_column(String(64), default="")
    last_timestamp: Mapped[int] = mapped_column(BigInteger, default=0)
    meta: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
