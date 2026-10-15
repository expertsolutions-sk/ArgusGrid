"""Audit viewing and export (ARG-009). Hidden-administrator rules apply to views and exports (IDN-031)."""
from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import forbidden
from app.core.permissions import ADMINISTRATOR, Cap
from app.models.identity import Role, User
from app.models.system import AuditRecord
from app.services.user_service import Viewer

MAX_PAGE_SIZE = 200
EXPORT_LIMIT = 10_000
NEUTRAL_ACTOR = "System"


def _csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


class AuditQuery:
    def __init__(self, session: Session) -> None:
        self._s = session

    def _admin_ids(self) -> list[str]:
        rows = self._s.execute(
            select(User.id).join(Role, User.role_id == Role.id).where(Role.name == ADMINISTRATOR)
        ).scalars()
        return [str(i) for i in rows]

    def _filtered(self, viewer: Viewer, f: dict[str, Any]):  # type: ignore[no-untyped-def]
        stmt = select(AuditRecord)
        if not viewer.can_view_admins:
            admin_ids = self._admin_ids()
            # Rows about administrator accounts are removed. Actions performed by administrators stay
            # visible, but the actor is shown as "System" (see _mask).
            stmt = stmt.where(~((AuditRecord.object_type == "user") & AuditRecord.object_id.in_(admin_ids)))
        if f.get("date_from"):
            stmt = stmt.where(AuditRecord.ts >= f["date_from"])
        if f.get("date_to"):
            stmt = stmt.where(AuditRecord.ts <= f["date_to"])
        if f.get("action"):
            stmt = stmt.where(AuditRecord.action.like(f["action"].replace("%", "") + "%"))
        if f.get("object_type"):
            stmt = stmt.where(AuditRecord.object_type == f["object_type"])
        if f.get("result"):
            stmt = stmt.where(AuditRecord.result == f["result"])
        if f.get("actor"):
            if viewer.can_view_admins:
                stmt = stmt.where(func.lower(AuditRecord.actor_name) == f["actor"].lower())
            else:  # never filter on a name that is masked
                stmt = stmt.where(func.lower(AuditRecord.actor_name) == f["actor"].lower(),
                                  AuditRecord.actor_role != ADMINISTRATOR)
        if f.get("q"):
            like = f"%{f['q'].lower()}%"
            stmt = stmt.where(or_(func.lower(AuditRecord.action).like(like), func.lower(AuditRecord.reason).like(like),
                                  func.lower(AuditRecord.object_id).like(like)))
        return stmt

    @staticmethod
    def _mask(viewer: Viewer, row: AuditRecord) -> dict[str, Any]:
        masked = row.actor_role == ADMINISTRATOR and not viewer.can_view_admins
        return {
            "id": row.id, "ts": row.ts.isoformat(),
            "actor": NEUTRAL_ACTOR if masked else row.actor_name,
            "actor_role": "" if masked else row.actor_role,
            "channel": row.channel, "source_ip": "" if masked else row.source_ip,
            "action": row.action, "object_type": row.object_type, "object_id": row.object_id,
            "result": row.result, "reason": row.reason,
            "changes": {} if masked and row.object_type == "user" else row.changes,
            "details": {} if masked else row.details,
        }

    def page(self, viewer: Viewer, filters: dict[str, Any], page: int, page_size: int) -> dict[str, Any]:
        if not viewer.has(Cap.AUDIT_VIEW):
            raise forbidden()
        page = max(1, page)
        page_size = min(max(1, page_size), MAX_PAGE_SIZE)
        stmt = self._filtered(viewer, filters)
        total = self._s.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
        rows = self._s.execute(
            stmt.order_by(AuditRecord.id.desc()).offset((page - 1) * page_size).limit(page_size)
        ).scalars().all()
        return {"items": [self._mask(viewer, r) for r in rows], "total": total, "page": page,
                "page_size": page_size}

    def export_csv(self, viewer: Viewer, filters: dict[str, Any]) -> str:
        if not viewer.has(Cap.AUDIT_EXPORT):
            raise forbidden()
        rows = self._s.execute(
            self._filtered(viewer, filters).order_by(AuditRecord.id).limit(EXPORT_LIMIT)
        ).scalars()
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["id", "timestamp_utc", "actor", "actor_role", "channel", "source_ip", "action",
                         "object_type", "object_id", "result", "reason", "changes", "details"])
        import json

        for row in rows:
            m = self._mask(viewer, row)
            writer.writerow([
                m["id"], m["ts"], _csv_safe(m["actor"]), _csv_safe(m["actor_role"]), m["channel"], m["source_ip"],
                m["action"], m["object_type"], _csv_safe(m["object_id"]), m["result"], _csv_safe(m["reason"]),
                _csv_safe(json.dumps(m["changes"], sort_keys=True, ensure_ascii=False)),
                _csv_safe(json.dumps(m["details"], sort_keys=True, ensure_ascii=False)),
            ])
        return buffer.getvalue()


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
