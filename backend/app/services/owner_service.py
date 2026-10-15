"""Emergency Owner support (rules/19 section 6): sealed verifier file, fail-closed, own rate limit.

The plaintext secret never exists here. The sealed file holds an identifier hash and a verifier.
The generation tool lives in devtools/ and is never part of a package (OWN-006, DEP-010).
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.clock import Clock
from app.core.security import constant_time_equals, verify_password
from app.models.system import OwnerAttempt
from app.services.settings_store import SettingsStore

INSTALLATION_KEY = "installation"
SEAL_VERSION = 1
OWNER_MAX_FAILURES = 5
OWNER_WINDOW = timedelta(minutes=15)


def identifier_digest(installation_id: str, identifier: str) -> str:
    return hashlib.sha256(f"{installation_id}:{identifier.strip().lower()}".encode("utf-8")).hexdigest()


def seal_checksum(installation_id: str, id_digest: str, verifier: str) -> str:
    """Detects accidental or careless edits. It is not a secret: it cannot stop someone with write access."""
    data = json.dumps(
        {"v": SEAL_VERSION, "installation_id": installation_id, "identifier_digest": id_digest, "verifier": verifier},
        sort_keys=True, separators=(",", ":"),
    )
    return base64.b64encode(hashlib.sha256(data.encode("utf-8")).digest()).decode("ascii")


@dataclass(frozen=True)
class SealedOwner:
    installation_id: str
    identifier_digest: str
    verifier: str


def read_sealed_file(path: Path) -> SealedOwner | None:
    """Load and check the sealed file. Any problem returns None (OWN-012: fail closed, no fallback)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        installation_id = str(raw["installation_id"])
        id_digest = str(raw["identifier_digest"])
        verifier = str(raw["verifier"])
        if int(raw["version"]) != SEAL_VERSION:
            return None
        if not constant_time_equals(str(raw["checksum"]), seal_checksum(installation_id, id_digest, verifier)):
            return None
        return SealedOwner(installation_id, id_digest, verifier)
    except (OSError, ValueError, KeyError, TypeError):
        return None


class OwnerService:
    def __init__(self, session: Session, clock: Clock, store: SettingsStore, sealed_path: Path) -> None:
        self._session = session
        self._clock = clock
        self._store = store
        self._sealed_path = sealed_path

    # -- availability -------------------------------------------------------------------------------
    def _sealed(self) -> SealedOwner | None:
        sealed = read_sealed_file(self._sealed_path)
        if sealed is None:
            return None
        installation = self._store.get(INSTALLATION_KEY) or {}
        # OWN-007: the file must belong to this installation.
        if installation.get("id") != sealed.installation_id:
            return None
        return sealed

    def is_available(self) -> bool:
        return self._sealed() is not None

    # -- rate limit (OWN-010) -----------------------------------------------------------------------
    def _blocked(self) -> bool:
        since = self._clock.now() - OWNER_WINDOW
        count = self._session.execute(
            select(func.count()).select_from(OwnerAttempt).where(OwnerAttempt.at >= since)
        ).scalar_one()
        return count >= OWNER_MAX_FAILURES

    def _note_failure(self, source_ip: str) -> None:
        self._session.add(OwnerAttempt(at=self._clock.now(), source_ip=source_ip))
        cutoff = self._clock.now() - timedelta(days=1)
        self._session.execute(delete(OwnerAttempt).where(OwnerAttempt.at < cutoff))

    # -- verification -------------------------------------------------------------------------------
    def verify(self, identifier: str, secret: str, source_ip: str) -> bool:
        """Always spends one password verification, whether or not the owner path is available."""
        sealed = self._sealed()
        blocked = self._blocked() if sealed is not None else False
        verifier = sealed.verifier if (sealed is not None and not blocked) else None
        secret_ok = verify_password(secret, verifier)
        id_ok = False
        if sealed is not None:
            id_ok = constant_time_equals(
                identifier_digest(sealed.installation_id, identifier), sealed.identifier_digest
            )
        ok = bool(secret_ok and id_ok and sealed is not None and not blocked)
        if not ok and sealed is not None and not blocked:
            self._note_failure(source_ip)
        if ok:
            self._session.execute(delete(OwnerAttempt))
        return ok
