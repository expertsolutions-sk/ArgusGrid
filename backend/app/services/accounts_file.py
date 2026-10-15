"""Ignored credential file for generated initial accounts (IDN-012, D-09).

The file lives under data/ (listed in .gitignore, excluded from packages). When the user changes the
password the plaintext line is replaced, so the file does not keep a password that is no longer valid.
"""
from __future__ import annotations

from pathlib import Path

HEADER = "# ArgusGrid initial accounts (generated). Keep private. Delete after the first password change.\n"


class AccountsFile:
    def __init__(self, path: Path) -> None:
        self._path = path

    def write_initial(self, username: str, password: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        existing = self._read_lines()
        lines = [line for line in existing if not line.startswith(f"{username}:")]
        lines.append(f"{username}: {password}")
        self._write(lines)

    def mark_changed(self, username: str) -> None:
        lines = self._read_lines()
        changed = False
        for i, line in enumerate(lines):
            if line.startswith(f"{username}:"):
                lines[i] = f"{username}: (password changed by the user, no longer valid here)"
                changed = True
        if changed:
            self._write(lines)

    def _read_lines(self) -> list[str]:
        try:
            return [ln for ln in self._path.read_text(encoding="utf-8").splitlines() if ln and not ln.startswith("#")]
        except OSError:
            return []

    def _write(self, lines: list[str]) -> None:
        self._path.write_text(HEADER + "\n".join(lines) + "\n", encoding="utf-8")
