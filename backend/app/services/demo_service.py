"""Demo data profile (DEP-050): create, reset and delete the fictional site. Creating twice does not duplicate.

Device secrets are random, shown once on the console and saved to the ignored file data/demo-devices.txt,
which the simulator reads (IDN-014, DEP-051). Demo rows are marked and only they are touched by delete.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.context import RequestContext, system_context
from app.core.crypto import SecretBox
from app.demo import krec
from app.models.assets import Asset, AssetRelation, AssetSoftware, DeviceCredential, Zone
from app.services import asset_vocab as vocab
from app.services.audit_service import AuditService
from app.services.device_credentials import DeviceCredentialService, ReplayCache
from app.services.user_service import OWNER_LEVEL, Viewer


@dataclass
class DemoReport:
    zones: int = 0
    assets: int = 0
    relations: int = 0
    credentials: int = 0
    secrets: dict[str, tuple[str, str]] = field(default_factory=dict)  # asset code -> (key_id, secret)


class DemoService:
    def __init__(self, session: Session, clock: Clock, box: SecretBox, audit: AuditService,
                 intel: Any = None) -> None:
        self._intel = intel
        self._s = session
        self._clock = clock
        self._box = box
        self._audit = audit

    def _viewer(self) -> Viewer:
        ctx: RequestContext = system_context("cli")
        return Viewer(ctx=ctx, capabilities=frozenset(), level=OWNER_LEVEL, role_name="", user_id=None, is_owner=True)

    def create(self, device_networks: list[str] | None = None) -> DemoReport:
        report = DemoReport()
        now = self._clock.now()
        networks = device_networks or ["10.20.50.0/24", "127.0.0.0/8"]
        for n in networks:
            ipaddress.ip_network(n, strict=False)

        zones: dict[str, Zone] = {z.code: z for z in self._s.execute(select(Zone)).scalars()}
        for spec in krec.ZONES:
            if spec["code"] in zones:
                continue
            zone = Zone(code=spec["code"], name=spec["name"], criticality=spec["criticality"],
                        polygon=spec["polygon"], description=spec["description"], is_demo=True)
            self._s.add(zone)
            zones[zone.code] = zone
            report.zones += 1
        self._s.flush()

        existing = {a.code: a for a in self._s.execute(select(Asset)).scalars().unique()}
        for spec in krec.ASSETS:
            if spec["code"] in existing:
                continue
            asset = Asset(
                code=spec["code"], name=spec["name"], asset_type=spec["asset_type"],
                category=vocab.TYPES[spec["asset_type"]], purdue_level=spec["purdue_level"],
                zone=zones.get(spec["zone"]), location=spec["location"], x=spec["x"], y=spec["y"],
                criticality=spec["criticality"], status="active", exposure=spec["exposure"],
                vendor=spec["vendor"], model=spec["model"], firmware_version=spec["firmware_version"],
                ip_address=spec["ip_address"], mac_address="", protocols=spec["protocols"], notes=spec["notes"],
                is_demo=True, created_at=now, updated_at=now,
            )
            for sw in spec["software"]:
                asset.software.append(AssetSoftware(**sw))
            self._s.add(asset)
            existing[asset.code] = asset
            report.assets += 1
        self._s.flush()

        have = {(r.source_id, r.target_id, r.relation) for r in self._s.execute(select(AssetRelation)).scalars()}
        for source, target, relation, protocol, note in krec.RELATIONS:
            s, t = existing[source], existing[target]
            if (s.id, t.id, relation) in have:
                continue
            self._s.add(AssetRelation(source_id=s.id, target_id=t.id, relation=relation, protocol=protocol, note=note))
            report.relations += 1
        self._s.flush()

        # Device credentials only for assets that have none yet (the secret of an old one cannot be shown again).
        devices = DeviceCredentialService(self._s, self._clock, self._box, self._audit, ReplayCache())
        viewer = self._viewer()
        for code, asset in existing.items():
            if not asset.is_demo or asset.asset_type not in vocab.INGEST_TYPES:
                continue
            prefix = code.split("-")[0]
            scope = krec.SCOPE_BY_PREFIX.get(prefix)
            if scope is None and code not in krec.GATEWAYS_WITH_CREDENTIALS:
                continue
            already = self._s.execute(
                select(DeviceCredential.id).where(DeviceCredential.asset_id == asset.id)
            ).first()
            if already is not None:
                continue
            scopes = [scope] if scope else ["ingest:heartbeat"]
            if code in krec.GATEWAYS_WITH_CREDENTIALS:
                scopes = ["ingest:heartbeat", "ingest:cyber"]
            created = devices.create(viewer, asset.id, scopes=scopes, allowed_networks=networks, valid_days=365)
            report.secrets[code] = (created["key_id"], created["secret"])
            report.credentials += 1
        self._s.flush()
        if self._intel is not None:
            from app.demo.intel_demo import demo_records

            self._intel.import_payload(None, "records", demo_records(now), source_key="demo", is_demo=True)
        self._audit.record("demo.create", viewer.ctx, object_type="demo", object_id="krec",
                           details={"zones": report.zones, "assets": report.assets, "relations": report.relations,
                                    "credentials": report.credentials})
        return report

    def delete(self) -> DemoReport:
        """Remove only rows marked as demo. Assets cascade to software, relations and credentials."""
        report = DemoReport()
        if self._intel is not None:
            self._intel.purge_demo()
        ids = list(self._s.execute(select(Asset.id).where(Asset.is_demo.is_(True))).scalars())
        if ids:
            self._s.execute(delete(Asset).where(Asset.id.in_(ids)))
        report.assets = len(ids)
        removed_zones = self._s.execute(delete(Zone).where(Zone.is_demo.is_(True)))
        report.zones = removed_zones.rowcount or 0
        self._audit.record("demo.delete", self._viewer().ctx, object_type="demo", object_id="krec",
                           details={"assets": report.assets, "zones": report.zones})
        return report


def write_secrets_file(path: Path, secrets_by_code: dict[str, tuple[str, str]], base_url: str) -> None:
    """Ignored file read by the simulator. One line per device: code, key id, secret."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# ArgusGrid demo device credentials (generated). Keep private; the simulator reads this file.",
             f"# base_url: {base_url}"]
    lines += [f"{code} {key_id} {secret}" for code, (key_id, secret) in sorted(secrets_by_code.items())]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

