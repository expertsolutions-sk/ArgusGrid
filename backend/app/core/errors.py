"""API errors. The server returns codes; the client maps them to catalogue messages (rules/16 section 3)."""
from __future__ import annotations

from typing import Any


class ApiError(Exception):
    def __init__(self, status: int, code: str, details: Any = None) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.details = details

    def body(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code}
        if self.details is not None:
            payload["details"] = self.details
        return payload


def unauthorized(code: str = "not_authenticated") -> ApiError:
    return ApiError(401, code)


def forbidden(code: str = "forbidden") -> ApiError:
    return ApiError(403, code)


def not_found(code: str = "not_found") -> ApiError:
    return ApiError(404, code)


def invalid(code: str, details: Any = None) -> ApiError:
    return ApiError(422, code, details)
