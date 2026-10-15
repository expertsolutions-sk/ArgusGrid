"""Signed offline intelligence bundles (defense profile): Ed25519 over a canonical JSON body.

A bundle carries already normalised records (see parsers.py) and is brought into the site on removable media.
The importer accepts it only when the signature verifies against a trusted public key (stored as a setting).
"""
from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

FORMAT = "argusgrid-intel-bundle"
VERSION = 1


class BundleError(ValueError):
    """The bundle is malformed, unsigned, signed by an unknown key or altered."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_keypair() -> tuple[str, str]:
    """Return (private key, public key), both base64 of the raw 32 bytes."""
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw_private).decode(), base64.b64encode(raw_public).decode()


def sign_bundle(records: list[dict[str, Any]], private_key_b64: str, key_id: str, created_at: str,
                source: str = "offline") -> dict[str, Any]:
    body = {"format": FORMAT, "version": VERSION, "created_at": created_at, "source": source, "records": records}
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    return {**body, "key_id": key_id, "signature": base64.b64encode(key.sign(_canonical(body))).decode()}


def verify_bundle(bundle: Any, trusted: dict[str, str]) -> list[dict[str, Any]]:
    """Return the records of a verified bundle. `trusted` maps key id to a base64 public key."""
    if not isinstance(bundle, dict) or bundle.get("format") != FORMAT:
        raise BundleError("bundle.format")
    if bundle.get("version") != VERSION or not isinstance(bundle.get("records"), list):
        raise BundleError("bundle.version")
    key_id = str(bundle.get("key_id", ""))
    public_b64 = trusted.get(key_id)
    if public_b64 is None:
        raise BundleError("bundle.unknown_key")
    try:
        signature = base64.b64decode(str(bundle.get("signature", "")), validate=True)
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))
    except (ValueError, TypeError) as exc:
        raise BundleError("bundle.signature_invalid") from exc
    body = {k: bundle[k] for k in ("format", "version", "created_at", "source", "records") if k in bundle}
    try:
        public.verify(signature, _canonical(body))
    except InvalidSignature as exc:
        raise BundleError("bundle.signature_invalid") from exc
    return list(bundle["records"])
