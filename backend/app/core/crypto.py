"""Encryption of stored secrets (SMTP password, queued credentials). AES-256-GCM with a key file.

The key file is created on first use under data/ (ignored by Git, excluded from packages).
Losing it makes stored secrets unreadable: the SMTP password must then be entered again.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "enc1:"


class SecretBox:
    def __init__(self, key_file: Path) -> None:
        self._key_file = key_file
        self._aes: AESGCM | None = None

    def _cipher(self) -> AESGCM:
        if self._aes is None:
            if self._key_file.is_file():
                key = base64.b64decode(self._key_file.read_text(encoding="ascii").strip())
            else:
                self._key_file.parent.mkdir(parents=True, exist_ok=True)
                key = AESGCM.generate_key(bit_length=256)
                # exclusive create so two processes cannot overwrite each other's key
                try:
                    fd = os.open(self._key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w", encoding="ascii") as handle:
                        handle.write(base64.b64encode(key).decode("ascii"))
                except FileExistsError:
                    key = base64.b64decode(self._key_file.read_text(encoding="ascii").strip())
            self._aes = AESGCM(key)
        return self._aes

    def encrypt(self, text: str) -> str:
        nonce = os.urandom(12)
        blob = nonce + self._cipher().encrypt(nonce, text.encode("utf-8"), None)
        return PREFIX + base64.b64encode(blob).decode("ascii")

    def decrypt(self, token: str) -> str | None:
        """Return the plaintext, or None when the token is not ours or cannot be authenticated."""
        if not token.startswith(PREFIX):
            return None
        try:
            blob = base64.b64decode(token[len(PREFIX):])
            return self._cipher().decrypt(blob[:12], blob[12:], None).decode("utf-8")
        except (InvalidTag, ValueError):
            return None
