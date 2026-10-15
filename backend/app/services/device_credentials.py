"""Device credentials and request authentication (ARG-013, IDN-014).

Every sensor and gateway has its own key, scopes, allowed source networks, expiry and signed requests.
A device can act only as its own asset. The secret is shown once and stored encrypted.
"""
from __future__ import annotations

import hmac
import ipaddress
import secrets
import time
from dataclasses import dataclass
from datetime import timedelta
from threading import Lock
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.crypto import SecretBox
from app.core.errors import ApiError, forbidden, invalid, not_found
from app.core.permissions import Cap
from app.core.signing import MAX_CLOCK_SKEW_SECONDS, sign
from app.models.assets import Asset, DeviceCredential
from app.services import asset_vocab as vocab
from app.services.audit_service import AuditService
from app.services.user_service import Viewer

DEFAULT_VALID_DAYS = 90
MAX_VALID_DAYS = 365
MAX_GRACE_MINUTES = 24 * 60


class ReplayCache:
    """Remembers recent (key, signature) pairs so a captured request cannot be sent again."""

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = Lock()

    def check_and_add(self, key_id: str, signature: str, now: float | None = None) -> bool:
        """True when the pair is new. The window is twice the allowed clock skew."""
        now = time.monotonic() if now is None else now
        horizon = 2 * MAX_CLOCK_SKEW_SECONDS
        with self._lock:
            if len(self._seen) > 10_000:
                self._seen = {k: t for k, t in self._seen.items() if now - t <= horizon}
            stamp = self._seen.get((key_id, signature))
            if stamp is not None and now - stamp <= horizon:
                return False
            self._seen[(key_id, signature)] = now
            return True


@dataclass(frozen=True)
class DeviceIdentity:
    asset_id: int
    asset_code: str
    key_id: str
    scopes: frozenset[str]


def device_auth_failed() -> ApiError:
    """One answer for every failure, so the endpoint is not an oracle for keys, networks or clocks."""
    return ApiError(401, "device_auth_failed")


class DeviceCredentialService:
    def __init__(self, session: Session, clock: Clock, box: SecretBox, audit: AuditService,
                 replay: ReplayCache | None = None) -> None:
        self._s = session
        self._clock = clock
        self._box = box
        self._audit = audit
        self._replay = replay or ReplayCache()

    # -- views --------------------------------------------------------------------------------------
    def _state(self, cred: DeviceCredential) -> str:
        now = self._clock.now()
        if cred.revoked_at is not None and cred.revoked_at <= now:
            return "revoked"
        if cred.expires_at <= now:
            return "expired"
        if cred.revoked_at is not None:
            return "retiring"  # rotated with a grace period: still valid until revoked_at
        return "active"

    def dto(self, cred: DeviceCredential, asset_code: str) -> dict[str, Any]:
        return {
            "key_id": cred.key_id, "asset": asset_code, "scopes": list(cred.scopes),
            "allowed_networks": list(cred.allowed_networks), "state": self._state(cred),
            "created_at": cred.created_at.isoformat(), "created_by": cred.created_by,
            "expires_at": cred.expires_at.isoformat(),
            "revoked_at": cred.revoked_at.isoformat() if cred.revoked_at else None,
            "last_used_at": cred.last_used_at.isoformat() if cred.last_used_at else None,
            "last_used_ip": cred.last_used_ip,
        }

    # -- management ---------------------------------------------------------------------------------
    @staticmethod
    def _require(viewer: Viewer, capability: str) -> None:
        if not viewer.has(capability):
            raise forbidden()

    def list_for_asset(self, viewer: Viewer, asset_id: int) -> list[dict[str, Any]]:
        self._require(viewer, Cap.ASSET_VIEW)
        asset = self._s.get(Asset, asset_id)
        if asset is None:
            raise not_found("asset.not_found")
        rows = self._s.execute(
            select(DeviceCredential).where(DeviceCredential.asset_id == asset_id).order_by(DeviceCredential.id.desc())
        ).scalars()
        return [self.dto(c, asset.code) for c in rows]

    def _check_input(self, scopes: list[str], networks: list[str], valid_days: int) -> list[str]:
        problems: list[dict[str, Any]] = []
        if not scopes or any(s not in vocab.SCOPES for s in scopes):
            problems.append({"code": "device.scopes_invalid", "fields": ["scopes"]})
        cleaned: list[str] = []
        try:
            for net in networks:
                cleaned.append(str(ipaddress.ip_network(net.strip(), strict=False)))
        except ValueError:
            problems.append({"code": "device.networks_invalid", "fields": ["allowed_networks"]})
        if not networks:
            problems.append({"code": "device.networks_required", "fields": ["allowed_networks"]})
        if not 1 <= valid_days <= MAX_VALID_DAYS:
            problems.append({"code": "device.validity_invalid", "fields": ["valid_days"]})
        if problems:
            raise invalid("device.invalid", problems)
        return cleaned

    def _new(self, asset: Asset, scopes: list[str], networks: list[str], valid_days: int,
             created_by: str) -> tuple[DeviceCredential, str]:
        secret = "ds_" + secrets.token_urlsafe(32)
        now = self._clock.now()
        cred = DeviceCredential(
            asset_id=asset.id, key_id="dk_" + secrets.token_hex(8), secret_enc=self._box.encrypt(secret),
            scopes=sorted(set(scopes) | {"ingest:heartbeat"}), allowed_networks=networks, created_at=now,
            created_by=created_by, expires_at=now + timedelta(days=valid_days),
        )
        self._s.add(cred)
        self._s.flush()
        return cred, secret

    def create(self, viewer: Viewer, asset_id: int, *, scopes: list[str], allowed_networks: list[str],
               valid_days: int = DEFAULT_VALID_DAYS) -> dict[str, Any]:
        self._require(viewer, Cap.ASSET_CREDENTIAL_ROTATE)
        asset = self._s.get(Asset, asset_id)
        if asset is None:
            raise not_found("asset.not_found")
        if asset.asset_type not in vocab.INGEST_TYPES:
            raise invalid("device.invalid", [{"code": "device.type_not_allowed", "fields": ["asset"]}])
        if asset.status not in ("active", "maintenance", "planned"):
            raise ApiError(409, "device.asset_not_usable")
        networks = self._check_input(scopes, allowed_networks, valid_days)
        cred, secret = self._new(asset, scopes, networks, valid_days, viewer.ctx.actor.name or "system")
        self._audit.record("device.credential.create", viewer.ctx, object_type="asset", object_id=asset.id,
                           details={"key_id": cred.key_id, "scopes": cred.scopes, "networks": networks,
                                    "valid_days": valid_days})
        result = self.dto(cred, asset.code)
        result["secret"] = secret  # the only time it is returned
        return result

    def rotate(self, viewer: Viewer, key_id: str, *, grace_minutes: int = 0) -> dict[str, Any]:
        """New key with the same scopes and networks; the old one ends now or after a grace period."""
        self._require(viewer, Cap.ASSET_CREDENTIAL_ROTATE)
        old = self._by_key(key_id)
        if not 0 <= grace_minutes <= MAX_GRACE_MINUTES:
            raise invalid("device.invalid", [{"code": "device.grace_invalid", "fields": ["grace_minutes"]}])
        asset = self._s.get(Asset, old.asset_id)
        assert asset is not None
        if self._state(old) in ("revoked", "expired"):
            raise ApiError(409, "device.credential_not_active")
        now = self._clock.now()
        days = max(1, min(MAX_VALID_DAYS, (old.expires_at - old.created_at).days or DEFAULT_VALID_DAYS))
        new, secret = self._new(asset, list(old.scopes), list(old.allowed_networks), days,
                                viewer.ctx.actor.name or "system")
        old.revoked_at = now + timedelta(minutes=grace_minutes)
        self._audit.record("device.credential.rotate", viewer.ctx, object_type="asset", object_id=asset.id,
                           details={"old_key_id": old.key_id, "new_key_id": new.key_id,
                                    "grace_minutes": grace_minutes})
        result = self.dto(new, asset.code)
        result["secret"] = secret
        return result

    def revoke(self, viewer: Viewer, key_id: str) -> dict[str, Any]:
        self._require(viewer, Cap.ASSET_CREDENTIAL_ROTATE)
        cred = self._by_key(key_id)
        asset = self._s.get(Asset, cred.asset_id)
        assert asset is not None
        now = self._clock.now()
        if cred.revoked_at is None or cred.revoked_at > now:
            cred.revoked_at = now
        self._audit.record("device.credential.revoke", viewer.ctx, object_type="asset", object_id=asset.id,
                           details={"key_id": key_id})
        return self.dto(cred, asset.code)

    def _by_key(self, key_id: str) -> DeviceCredential:
        cred = self._s.execute(select(DeviceCredential).where(DeviceCredential.key_id == key_id)).scalar_one_or_none()
        if cred is None:
            raise not_found("device.credential_not_found")
        return cred

    # -- authentication of device requests ----------------------------------------------------------
    def authenticate(self, *, key_id: str, timestamp: str, signature: str, method: str, target: str,
                     body: bytes, source_ip: str, required_scope: str) -> DeviceIdentity:
        """Verify a signed device request. Every failure is the same answer and one audit record."""
        from app.core.context import ANONYMOUS_ACTOR, RequestContext

        ctx = RequestContext(actor=ANONYMOUS_ACTOR, channel="service", source_ip=source_ip)

        def fail(reason: str) -> ApiError:
            self._audit.record("device.auth_failed", ctx, object_type="device_key",
                               object_id=key_id[:32], result="failure", reason=reason)
            return device_auth_failed()

        cred = self._s.execute(
            select(DeviceCredential).where(DeviceCredential.key_id == key_id[:32])
        ).scalar_one_or_none() if key_id else None
        if cred is None:
            raise fail("unknown_key")
        now = self._clock.now()
        if self._state(cred) in ("revoked", "expired"):
            raise fail("credential_" + self._state(cred))
        asset = self._s.get(Asset, cred.asset_id)
        if asset is None or asset.status not in ("active", "maintenance"):
            raise fail("asset_not_active")
        try:
            ts = int(timestamp)
        except ValueError:
            raise fail("timestamp_invalid") from None
        if abs(int(now.timestamp()) - ts) > MAX_CLOCK_SKEW_SECONDS:
            raise fail("timestamp_out_of_window")
        try:
            address = ipaddress.ip_address(source_ip)
            allowed = any(address in ipaddress.ip_network(n, strict=False) for n in cred.allowed_networks)
        except ValueError:
            allowed = False
        if not allowed:
            raise fail("source_not_allowed")
        secret = self._box.decrypt(cred.secret_enc)
        if secret is None:
            raise fail("secret_unreadable")
        expected = sign(secret, method, target, timestamp, body)
        if not hmac.compare_digest(expected, signature.lower()):
            raise fail("bad_signature")
        if not self._replay.check_and_add(cred.key_id, expected):
            raise fail("replay")
        if required_scope not in cred.scopes:
            raise fail("scope_missing")
        cred.last_used_at = now
        cred.last_used_ip = source_ip
        cred.last_timestamp = ts
        asset.last_seen_at = now
        return DeviceIdentity(asset_id=asset.id, asset_code=asset.code, key_id=cred.key_id,
                              scopes=frozenset(cred.scopes))
