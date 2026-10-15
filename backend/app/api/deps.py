"""Request dependencies: services, principal, capability checks, CSRF (IDN-002, rules/03)."""
from __future__ import annotations

import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from typing import Callable, Iterator

from fastapi import Depends, Request

from app.core.config import AppConfig
from app.core.context import ANONYMOUS_ACTOR, Actor, RequestContext
from app.core.errors import ApiError, forbidden, unauthorized
from app.models.identity import SessionRecord, User
from app.services.container import Services
from app.services.user_service import OWNER_LEVEL, Viewer

COOKIE_NAME = "argus_session"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class SourceThrottle:
    """Per-address request limiter for the login endpoint (rules/18 section 2), independent of account locks."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str, limit_per_minute: int, now: float) -> bool:
        if limit_per_minute <= 0:
            return True
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > 60:
                hits.popleft()
            if len(hits) >= limit_per_minute:
                return False
            hits.append(now)
            return True


@dataclass
class Principal:
    actor: Actor
    user: User | None
    session: SessionRecord | None
    capabilities: frozenset[str]
    is_owner: bool = False
    dev_loginless: bool = False

    def has(self, capability: str) -> bool:
        return self.is_owner or capability in self.capabilities  # OWN-003: owner bypasses RBAC

    @property
    def must_change_password(self) -> bool:
        return bool(self.user and self.user.must_change_password)


def get_config(request: Request) -> AppConfig:
    return request.app.state.config


def get_services(request: Request) -> Iterator[Services]:
    """One database session per request. Commits on success and also on an ApiError, so failure
    counters and audit records of rejected requests are kept."""
    session = request.app.state.db.session()
    services = Services(session, request.app.state.clock, request.app.state.config, request.app.state.transport,
                        request.app.state.replay, request.app.state.hub)
    try:
        yield services
        session.commit()
    except ApiError:
        session.commit()
        raise
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def build_context(request: Request, actor: Actor = ANONYMOUS_ACTOR, session: SessionRecord | None = None,
                  channel: str | None = None) -> RequestContext:
    client = request.client.host if request.client else ""
    ref = session.token_digest[:8] if session is not None else ""
    return RequestContext(
        actor=actor,
        channel=channel or ("ui" if request.headers.get("x-argus-client") == "web" else "api"),
        source_ip=client,
        user_agent=request.headers.get("user-agent", ""),
        request_id=request.headers.get("x-request-id") or uuid.uuid4().hex,
        session_ref=ref,
    )


def _resolve_principal(request: Request, svc: Services) -> Principal | None:
    token = request.cookies.get(COOKIE_NAME)
    row = svc.sessions.resolve(token)
    if row is not None:
        if row.is_owner:
            return Principal(actor=Actor(kind="owner", name="System"), user=None, session=row,
                             capabilities=frozenset(), is_owner=True)
        user = svc.session.get(User, row.user_id) if row.user_id is not None else None
        if user is None or not user.is_active or svc.lockout.is_locked(user):
            svc.sessions.revoke(row)  # LCK-012: a lock ends the session on its next request
            return None
        actor = Actor(kind="service" if user.is_service else "user", name=user.username, role=user.role.name,
                      user_id=user.id)
        return Principal(actor=actor, user=user, session=row, capabilities=frozenset(user.role.capabilities))
    return _dev_principal(request, svc)


def _dev_principal(request: Request, svc: Services) -> Principal | None:
    """Development-only loginless path. The module is physically removed from packages (DEV-005)."""
    if not svc.config.dev_loginless:
        return None
    try:
        from app import dev_loginless
    except ImportError:
        return None
    return dev_loginless.principal_for(svc, Principal)


def _check_csrf(request: Request, principal: Principal) -> None:
    if request.method in SAFE_METHODS or principal.session is None:
        return
    supplied = request.headers.get(CSRF_HEADER, "")
    if not supplied or supplied != principal.session.csrf_token:
        raise forbidden("csrf_failed")


def optional_principal(request: Request, svc: Services = Depends(get_services)) -> Principal | None:
    principal = _resolve_principal(request, svc)
    if principal is not None:
        _check_csrf(request, principal)
    return principal


def principal_pending_ok(principal: Principal | None = Depends(optional_principal)) -> Principal:
    """Authenticated, even while a forced password change is outstanding."""
    if principal is None:
        raise unauthorized()
    return principal


def current_principal(principal: Principal = Depends(principal_pending_ok)) -> Principal:
    """Authenticated and free to use the application (IDN-013: nothing else works before the change)."""
    if principal.must_change_password:
        raise forbidden("password_change_required")
    return principal


def require(capability: str) -> Callable[..., Principal]:
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.has(capability):
            raise forbidden()
        return principal

    return dependency


def request_context(request: Request, principal: Principal = Depends(principal_pending_ok)) -> RequestContext:
    channel = "dev-loginless" if principal.dev_loginless else None
    return build_context(request, principal.actor, principal.session, channel)


def viewer(principal: Principal = Depends(current_principal),
           ctx: RequestContext = Depends(request_context)) -> Viewer:
    """The acting party as the user and role services need it (visibility, level, capabilities)."""
    if principal.is_owner:
        return Viewer(ctx=ctx, capabilities=frozenset(), level=OWNER_LEVEL, role_name="", user_id=None, is_owner=True)
    user = principal.user
    assert user is not None
    return Viewer(ctx=ctx, capabilities=principal.capabilities, level=user.role.security_level,
                  role_name=user.role.name, user_id=user.id)


# Sensors report a few times per second at most. Limits are per claimed key and, as a backstop, per address.
DEVICE_LIMIT_PER_KEY_PER_MINUTE = 1200
DEVICE_LIMIT_PER_IP_PER_MINUTE = 12000


def device_auth(required_scope: str) -> Callable[..., object]:
    """Dependency factory: authenticate a signed device request for one scope. Devices are not users."""
    from app.core.signing import HEADER_KEY, HEADER_SIGNATURE, HEADER_TIMESTAMP

    async def dependency(request: Request, svc: Services = Depends(get_services)):  # type: ignore[no-untyped-def]
        import time

        source = request.client.host if request.client else ""
        claimed = request.headers.get(HEADER_KEY, "")[:40]
        throttle = request.app.state.throttle
        now = time.monotonic()
        if not throttle.allow(f"device-ip:{source}", DEVICE_LIMIT_PER_IP_PER_MINUTE, now) or                 not throttle.allow(f"device-key:{claimed}", DEVICE_LIMIT_PER_KEY_PER_MINUTE, now):
            raise ApiError(429, "too_many_requests")
        body = await request.body()
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        return svc.devices.authenticate(
            key_id=request.headers.get(HEADER_KEY, ""), timestamp=request.headers.get(HEADER_TIMESTAMP, ""),
            signature=request.headers.get(HEADER_SIGNATURE, ""), method=request.method, target=target,
            body=body, source_ip=source, required_scope=required_scope,
        )

    return dependency
