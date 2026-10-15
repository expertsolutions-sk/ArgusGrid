"""Asset registry: devices, communication nodes and endpoints, with software and relations (ARG-012)."""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.errors import ApiError, forbidden, invalid, not_found
from app.core.permissions import Cap
from app.models.assets import Asset, AssetRelation, AssetSoftware, DeviceCredential, Zone
from app.services import asset_vocab as vocab
from app.services.audit_service import AuditService, diff
from app.services.user_service import Viewer

CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,47}$")
MAC = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
EDITABLE = (
    "name", "asset_type", "purdue_level", "zone", "location", "x", "y", "criticality", "status", "exposure",
    "vendor", "model", "firmware_version", "ip_address", "mac_address", "protocols", "notes",
)
MAX_PAGE_SIZE = 200


class AssetService:
    def __init__(self, session: Session, clock: Clock, audit: AuditService) -> None:
        self._s = session
        self._clock = clock
        self._audit = audit

    # -- helpers ------------------------------------------------------------------------------------
    @staticmethod
    def _require(viewer: Viewer, capability: str) -> None:
        if not viewer.has(capability):
            raise forbidden()

    def _zone(self, code: str | None) -> Zone | None:
        if not code:
            return None
        zone = self._s.execute(select(Zone).where(Zone.code == code)).scalar_one_or_none()
        if zone is None:
            raise invalid("asset.invalid", [{"code": "asset.zone_unknown", "fields": ["zone"]}])
        return zone

    def _get(self, asset_id: int) -> Asset:
        asset = self._s.get(Asset, asset_id)
        if asset is None:
            raise not_found("asset.not_found")
        return asset

    def dto(self, asset: Asset, *, detail: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": asset.id, "code": asset.code, "name": asset.name, "asset_type": asset.asset_type,
            "category": asset.category, "purdue_level": asset.purdue_level,
            "zone": asset.zone.code if asset.zone else None, "location": asset.location,
            "x": asset.x, "y": asset.y, "criticality": asset.criticality, "status": asset.status,
            "exposure": list(asset.exposure or []), "vendor": asset.vendor, "model": asset.model,
            "firmware_version": asset.firmware_version, "ip_address": asset.ip_address,
            "mac_address": asset.mac_address, "protocols": list(asset.protocols or []), "notes": asset.notes,
            "is_demo": asset.is_demo,
            "last_seen_at": asset.last_seen_at.isoformat() if asset.last_seen_at else None,
            "can_ingest": asset.asset_type in vocab.INGEST_TYPES,
            "software_count": len(asset.software),
        }
        if detail:
            data["software"] = [
                {"name": s.name, "vendor": s.vendor, "version": s.version, "cpe": s.cpe} for s in asset.software
            ]
            data["relations"] = self.relations_of(asset.id)
        return data

    @staticmethod
    def vocabulary() -> dict[str, Any]:
        return {
            "types": vocab.TYPES, "levels": list(vocab.LEVELS), "criticality": list(vocab.CRITICALITY),
            "statuses": list(vocab.STATUSES), "exposure": list(vocab.EXPOSURE),
            "relations": list(vocab.RELATIONS), "scopes": list(vocab.SCOPES),
            "ingest_types": list(vocab.INGEST_TYPES), "transitions": {k: list(v) for k, v in vocab.TRANSITIONS.items()},
        }

    def zones(self, viewer: Viewer) -> list[dict[str, Any]]:
        self._require(viewer, Cap.ASSET_VIEW)
        rows = list(self._s.execute(select(Zone).order_by(Zone.code)).scalars())
        counts = dict(self._s.execute(select(Asset.zone_id, func.count()).group_by(Asset.zone_id)).all())
        from app.services.airspace import ZoneShape, background_zone_codes

        shapes = [ZoneShape(z.code, z.criticality, tuple((float(p[0]), float(p[1])) for p in z.polygon))
                  for z in rows if z.polygon]
        background = background_zone_codes(shapes)
        return [{"id": z.id, "code": z.code, "name": z.name, "criticality": z.criticality, "polygon": z.polygon,
                 "description": z.description, "asset_count": counts.get(z.id, 0),
                 "background": z.code in background} for z in rows]

    # -- read ---------------------------------------------------------------------------------------
    def list(self, viewer: Viewer, *, search: str = "", asset_type: str = "", zone: str = "", status: str = "",
             level: str = "", category: str = "", page: int = 1, page_size: int = 20) -> dict[str, Any]:
        self._require(viewer, Cap.ASSET_VIEW)
        page = max(1, page)
        page_size = min(max(1, page_size), MAX_PAGE_SIZE)
        stmt = select(Asset)
        if search.strip():
            like = f"%{search.strip().lower()}%"
            stmt = stmt.where(or_(func.lower(Asset.code).like(like), func.lower(Asset.name).like(like),
                                  func.lower(Asset.ip_address).like(like), func.lower(Asset.vendor).like(like)))
        if asset_type:
            stmt = stmt.where(Asset.asset_type == asset_type)
        if category:
            stmt = stmt.where(Asset.category == category)
        if status:
            stmt = stmt.where(Asset.status == status)
        if level:
            stmt = stmt.where(Asset.purdue_level == level)
        if zone:
            stmt = stmt.where(Asset.zone.has(code=zone))
        total = self._s.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        rows = self._s.execute(
            stmt.order_by(Asset.code).offset((page - 1) * page_size).limit(page_size)
        ).scalars().unique().all()
        return {"items": [self.dto(a) for a in rows], "total": total, "page": page, "page_size": page_size}

    def get(self, viewer: Viewer, asset_id: int) -> dict[str, Any]:
        self._require(viewer, Cap.ASSET_VIEW)
        return self.dto(self._get(asset_id), detail=True)

    def relations_of(self, asset_id: int) -> dict[str, list[dict[str, Any]]]:
        rows = self._s.execute(
            select(AssetRelation).where(or_(AssetRelation.source_id == asset_id, AssetRelation.target_id == asset_id))
        ).scalars().all()
        ids = {r.source_id for r in rows} | {r.target_id for r in rows}
        codes = dict(self._s.execute(select(Asset.id, Asset.code).where(Asset.id.in_(ids))).all()) if ids else {}
        out: dict[str, list[dict[str, Any]]] = {"outgoing": [], "incoming": []}
        for r in rows:
            item = {"id": r.id, "relation": r.relation, "protocol": r.protocol, "note": r.note,
                    "source": codes.get(r.source_id, ""), "target": codes.get(r.target_id, "")}
            (out["outgoing"] if r.source_id == asset_id else out["incoming"]).append(item)
        return out

    # -- validation ---------------------------------------------------------------------------------
    def _validate(self, data: dict[str, Any], *, creating: bool) -> list[dict[str, Any]]:
        problems: list[dict[str, Any]] = []

        def bad(code: str, field: str) -> None:
            problems.append({"code": code, "fields": [field]})

        if creating and not CODE.match(str(data.get("code", ""))):
            bad("asset.code_invalid", "code")
        if "name" in data and not (1 <= len(str(data["name"]).strip()) <= 128):
            bad("asset.name_invalid", "name")
        if "asset_type" in data and data["asset_type"] not in vocab.TYPES:
            bad("asset.type_invalid", "asset_type")
        if "purdue_level" in data and data["purdue_level"] not in (*vocab.LEVELS, ""):
            bad("asset.level_invalid", "purdue_level")
        if "criticality" in data and data["criticality"] not in vocab.CRITICALITY:
            bad("asset.criticality_invalid", "criticality")
        if "status" in data and data["status"] not in vocab.STATUSES:
            bad("asset.status_invalid", "status")
        if "exposure" in data:
            exp = data["exposure"]
            if not isinstance(exp, list) or any(e not in vocab.EXPOSURE for e in exp):
                bad("asset.exposure_invalid", "exposure")
        if "protocols" in data:
            prot = data["protocols"]
            if not isinstance(prot, list) or any(not isinstance(p, str) or len(p) > 48 for p in prot):
                bad("asset.protocols_invalid", "protocols")
        if data.get("ip_address"):
            try:
                ipaddress.ip_address(str(data["ip_address"]))
            except ValueError:
                bad("asset.ip_invalid", "ip_address")
        if data.get("mac_address") and not MAC.match(str(data["mac_address"])):
            bad("asset.mac_invalid", "mac_address")
        for axis in ("x", "y"):
            value = data.get(axis)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                      or not -100000 <= float(value) <= 100000):
                bad("asset.coordinate_invalid", axis)
        for text_field, limit in (("location", 128), ("vendor", 64), ("model", 64), ("firmware_version", 48),
                                  ("notes", 2000)):
            if text_field in data and len(str(data[text_field])) > limit:
                bad("asset.text_too_long", text_field)
        return problems

    # -- write --------------------------------------------------------------------------------------
    @staticmethod
    def _snapshot(asset: Asset) -> dict[str, Any]:
        return {
            "code": asset.code, "name": asset.name, "asset_type": asset.asset_type,
            "purdue_level": asset.purdue_level, "zone": asset.zone.code if asset.zone else None,
            "location": asset.location, "x": asset.x, "y": asset.y, "criticality": asset.criticality,
            "status": asset.status, "exposure": sorted(asset.exposure or []), "vendor": asset.vendor,
            "model": asset.model, "firmware_version": asset.firmware_version, "ip_address": asset.ip_address,
            "mac_address": asset.mac_address, "protocols": list(asset.protocols or []), "notes": asset.notes,
        }

    def create(self, viewer: Viewer, data: dict[str, Any]) -> dict[str, Any]:
        self._require(viewer, Cap.ASSET_CREATE)
        unknown = set(data) - set(EDITABLE) - {"code"}
        if unknown:
            raise invalid("asset.invalid", [{"code": "asset.field_unknown", "fields": sorted(unknown)}])
        problems = self._validate(data, creating=True)
        for required in ("name", "asset_type"):
            if required not in data:
                problems.append({"code": f"asset.{required}_invalid", "fields": [required]})
        if problems:
            raise invalid("asset.invalid", problems)
        code = str(data["code"])
        if self._s.execute(select(Asset.id).where(func.lower(Asset.code) == code.lower())).first() is not None:
            raise ApiError(409, "asset.code_taken")
        now = self._clock.now()
        asset = Asset(
            code=code, name=str(data["name"]).strip(), asset_type=data["asset_type"],
            category=vocab.TYPES[data["asset_type"]], purdue_level=str(data.get("purdue_level", "")),
            zone=self._zone(data.get("zone")), location=str(data.get("location", "")),
            x=data.get("x"), y=data.get("y"), criticality=data.get("criticality", "medium"),
            status=data.get("status", "active"), exposure=list(data.get("exposure", [])),
            vendor=str(data.get("vendor", "")), model=str(data.get("model", "")),
            firmware_version=str(data.get("firmware_version", "")), ip_address=str(data.get("ip_address", "")),
            mac_address=str(data.get("mac_address", "")), protocols=list(data.get("protocols", [])),
            notes=str(data.get("notes", "")), is_demo=False, created_at=now, updated_at=now,
        )
        self._s.add(asset)
        self._s.flush()
        self._audit.record("asset.create", viewer.ctx, object_type="asset", object_id=asset.id,
                           changes=diff({}, self._snapshot(asset)))
        return self.dto(asset, detail=True)

    def update(self, viewer: Viewer, asset_id: int, data: dict[str, Any]) -> dict[str, Any]:
        self._require(viewer, Cap.ASSET_EDIT)
        asset = self._get(asset_id)
        unknown = set(data) - set(EDITABLE)
        if unknown:  # also refuses "code": the identifier is stable
            raise invalid("asset.invalid", [{"code": "asset.field_unknown", "fields": sorted(unknown)}])
        problems = self._validate(data, creating=False)
        if "status" in data and data["status"] not in vocab.TRANSITIONS.get(asset.status, ()):
            problems.append({"code": "asset.status_transition", "fields": ["status"]})
        if problems:
            raise invalid("asset.invalid", problems)
        before = self._snapshot(asset)
        if "name" in data:
            asset.name = str(data["name"]).strip()
        if "asset_type" in data and data["asset_type"] != asset.asset_type:
            if asset.asset_type in vocab.INGEST_TYPES and data["asset_type"] not in vocab.INGEST_TYPES and \
                    self._active_credentials(asset.id) > 0:
                raise ApiError(409, "asset.type_has_credentials")
            asset.asset_type = data["asset_type"]
            asset.category = vocab.TYPES[data["asset_type"]]
        for key in ("purdue_level", "location", "criticality", "status", "vendor", "model", "firmware_version",
                    "ip_address", "mac_address", "notes", "x", "y"):
            if key in data:
                setattr(asset, key, data[key])
        if "zone" in data:
            asset.zone = self._zone(data["zone"])
        if "exposure" in data:
            asset.exposure = list(data["exposure"])
        if "protocols" in data:
            asset.protocols = list(data["protocols"])
        asset.updated_at = self._clock.now()
        self._s.flush()
        if asset.status == "decommissioned":
            self._revoke_credentials(asset.id)
        self._audit.record("asset.update", viewer.ctx, object_type="asset", object_id=asset.id,
                           changes=diff(before, self._snapshot(asset)))
        return self.dto(asset, detail=True)

    def delete(self, viewer: Viewer, asset_id: int) -> None:
        self._require(viewer, Cap.ASSET_DELETE)
        asset = self._get(asset_id)
        if asset.status not in ("planned", "decommissioned"):
            raise ApiError(409, "asset.delete_requires_decommission")
        self._audit.record("asset.delete", viewer.ctx, object_type="asset", object_id=asset.id,
                           changes=diff(self._snapshot(asset), {}))
        self._s.delete(asset)
        self._s.flush()

    # -- software -----------------------------------------------------------------------------------
    def set_software(self, viewer: Viewer, asset_id: int, items: list[dict[str, Any]]) -> dict[str, Any]:
        self._require(viewer, Cap.ASSET_EDIT)
        asset = self._get(asset_id)
        problems: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        clean: list[AssetSoftware] = []
        for item in items:
            name = str(item.get("name", "")).strip()
            version = str(item.get("version", "")).strip()
            if not name or len(name) > 96 or len(version) > 48 or len(str(item.get("vendor", ""))) > 64 \
                    or len(str(item.get("cpe", ""))) > 255:
                problems.append({"code": "asset.software_invalid", "fields": ["software"]})
                continue
            if (name.lower(), version) in seen:
                problems.append({"code": "asset.software_duplicate", "fields": ["software"]})
                continue
            seen.add((name.lower(), version))
            clean.append(AssetSoftware(name=name, vendor=str(item.get("vendor", "")).strip(), version=version,
                                       cpe=str(item.get("cpe", "")).strip()))
        if problems:
            raise invalid("asset.invalid", problems)
        before = [{"name": s.name, "version": s.version} for s in asset.software]
        asset.software.clear()
        self._s.flush()
        asset.software.extend(clean)
        asset.updated_at = self._clock.now()
        self._s.flush()
        after = [{"name": s.name, "version": s.version} for s in asset.software]
        self._audit.record("asset.software.update", viewer.ctx, object_type="asset", object_id=asset.id,
                           changes=diff({"software": before}, {"software": after}))
        return self.dto(asset, detail=True)

    # -- relations ----------------------------------------------------------------------------------
    def add_relation(self, viewer: Viewer, asset_id: int, *, target_code: str, relation: str, protocol: str,
                     note: str, direction: str = "outgoing") -> dict[str, Any]:
        self._require(viewer, Cap.ASSET_EDIT)
        asset = self._get(asset_id)
        other = self._s.execute(select(Asset).where(Asset.code == target_code)).scalar_one_or_none()
        problems: list[dict[str, Any]] = []
        if other is None:
            problems.append({"code": "asset.relation_target_unknown", "fields": ["target"]})
        elif other.id == asset.id:
            problems.append({"code": "asset.relation_self", "fields": ["target"]})
        if relation not in vocab.RELATIONS:
            problems.append({"code": "asset.relation_invalid", "fields": ["relation"]})
        if len(protocol) > 48 or len(note) > 255:
            problems.append({"code": "asset.text_too_long", "fields": ["protocol", "note"]})
        if problems:
            raise invalid("asset.invalid", problems)
        assert other is not None
        source, target = (asset, other) if direction == "outgoing" else (other, asset)
        exists = self._s.execute(
            select(AssetRelation.id).where(AssetRelation.source_id == source.id, AssetRelation.target_id == target.id,
                                           AssetRelation.relation == relation)
        ).first()
        if exists is not None:
            raise ApiError(409, "asset.relation_exists")
        row = AssetRelation(source_id=source.id, target_id=target.id, relation=relation, protocol=protocol, note=note)
        self._s.add(row)
        self._s.flush()
        self._audit.record("asset.relation.add", viewer.ctx, object_type="asset", object_id=asset.id,
                           details={"source": source.code, "target": target.code, "relation": relation})
        return self.relations_of(asset.id)

    def remove_relation(self, viewer: Viewer, asset_id: int, relation_id: int) -> dict[str, Any]:
        self._require(viewer, Cap.ASSET_EDIT)
        asset = self._get(asset_id)
        row = self._s.get(AssetRelation, relation_id)
        if row is None or asset.id not in (row.source_id, row.target_id):
            raise not_found("asset.relation_not_found")
        self._audit.record("asset.relation.remove", viewer.ctx, object_type="asset", object_id=asset.id,
                           details={"relation": row.relation, "source": row.source_id, "target": row.target_id})
        self._s.delete(row)
        self._s.flush()
        return self.relations_of(asset.id)

    # -- topology -----------------------------------------------------------------------------------
    def topology(self, viewer: Viewer) -> dict[str, Any]:
        self._require(viewer, Cap.ASSET_VIEW)
        assets = self._s.execute(select(Asset).where(Asset.status != "decommissioned")).scalars().unique().all()
        ids = {a.id for a in assets}
        edges = self._s.execute(select(AssetRelation)).scalars().all()
        return {
            "nodes": [
                {"id": a.id, "code": a.code, "name": a.name, "asset_type": a.asset_type, "category": a.category,
                 "purdue_level": a.purdue_level, "zone": a.zone.code if a.zone else None,
                 "criticality": a.criticality, "status": a.status, "x": a.x, "y": a.y}
                for a in assets
            ],
            "edges": [
                {"id": e.id, "source": e.source_id, "target": e.target_id, "relation": e.relation,
                 "protocol": e.protocol} for e in edges if e.source_id in ids and e.target_id in ids
            ],
        }

    # -- credentials interplay ----------------------------------------------------------------------
    def _active_credentials(self, asset_id: int) -> int:
        now = self._clock.now()
        return self._s.execute(
            select(func.count()).select_from(DeviceCredential).where(
                DeviceCredential.asset_id == asset_id, DeviceCredential.revoked_at.is_(None),
                DeviceCredential.expires_at > now)
        ).scalar_one()

    def _revoke_credentials(self, asset_id: int) -> None:
        now = self._clock.now()
        for cred in self._s.execute(
            select(DeviceCredential).where(DeviceCredential.asset_id == asset_id, DeviceCredential.revoked_at.is_(None))
        ).scalars():
            cred.revoked_at = now
