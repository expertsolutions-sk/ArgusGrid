"""Request signing for devices (ARG-013). Shared by the server and by device clients such as the simulator.

Signature = HMAC-SHA256(secret, METHOD "\n" TARGET "\n" TIMESTAMP "\n" SHA256(body)), hex encoded.
TARGET is the request path plus the raw query string, so a signed request cannot be replayed on another path.
"""
from __future__ import annotations

import hashlib
import hmac

HEADER_KEY = "x-device-key"
HEADER_TIMESTAMP = "x-device-timestamp"
HEADER_SIGNATURE = "x-device-signature"
MAX_CLOCK_SKEW_SECONDS = 120


def canonical(method: str, target: str, timestamp: int | str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{target}\n{timestamp}\n{body_hash}".encode("utf-8")


def sign(secret: str, method: str, target: str, timestamp: int | str, body: bytes = b"") -> str:
    return hmac.new(secret.encode("utf-8"), canonical(method, target, timestamp, body), hashlib.sha256).hexdigest()


def signed_headers(key_id: str, secret: str, method: str, target: str, timestamp: int, body: bytes = b"") -> dict[str, str]:
    return {
        "X-Device-Key": key_id,
        "X-Device-Timestamp": str(timestamp),
        "X-Device-Signature": sign(secret, method, target, timestamp, body),
    }
