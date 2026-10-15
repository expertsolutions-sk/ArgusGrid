"""Cryptographic helpers: password hashing (Argon2id), tokens, constant-time comparison.

Argon2id has no input truncation, which satisfies PWD-014 for the maximum length of the policy.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()

# A valid hash of a random value, used to spend the same time when the user does not exist (LCK-011).
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(24))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str | None) -> bool:
    """Verify a password. A missing hash is checked against a dummy so timing does not differ."""
    target = stored_hash or _DUMMY_HASH
    try:
        ok = _hasher.verify(target, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return bool(ok) and stored_hash is not None


def spend_verification_time(password: str) -> None:
    """Burn one verification so an unknown-user path costs the same as a known one."""
    verify_password(password, None)


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def new_token(nbytes: int = 32) -> str:
    """URL-safe token with 256 bits of entropy by default (rules/03)."""
    return secrets.token_urlsafe(nbytes)


def token_digest(token: str) -> str:
    """Only the digest of a session token is stored in the database."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
