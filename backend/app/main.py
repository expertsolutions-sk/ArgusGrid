"""Application entry point (rules/01): configuration, database, error mapping, routers, static client."""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import __version__

from contextlib import asynccontextmanager

from app.api import (
    assets_router, audit_router, auth_router, devices_router, email_router, incidents_router, intel_router,
    policy_router, roles_router, telemetry_router, users_router,
)
from app.api.deps import SourceThrottle
from app.core.clock import Clock
from app.core.config import AppConfig, load_config
from app.core.db import Database
from app.core.errors import ApiError
from app.services.device_credentials import ReplayCache
from app.services.intel_service import Fetcher, HttpFetcher
from app.services.mail_service import MailTransport, SmtpTransport
from app.services.stream import StreamHub
from app.workers import MailWorker

FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"


def create_app(config: AppConfig | None = None, clock: Clock | None = None, db: Database | None = None,
               transport: MailTransport | None = None, fetcher: Fetcher | None = None) -> FastAPI:
    config = config or load_config()

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
        worker: MailWorker | None = None
        if config.run_workers:
            interval = float(os.environ.get("ARGUS_WORKER_SECONDS", "30"))
            worker = MailWorker(app.state.db, app.state.clock, config, app.state.transport, interval,
                                app.state.fetcher)
            worker.start()
        try:
            yield
        finally:
            if worker is not None:
                worker.stop()

    app = FastAPI(title="ArgusGrid", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.config = config
    app.state.clock = clock or Clock()
    app.state.db = db or Database(config.database_url)
    app.state.throttle = SourceThrottle()
    app.state.transport = transport or SmtpTransport()
    app.state.replay = ReplayCache()
    app.state.hub = StreamHub()
    app.state.fetcher = fetcher or HttpFetcher()

    @app.exception_handler(ApiError)
    async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content=exc.body())

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo submitted values (they may contain passwords): location and type only.
        problems = [{"field": ".".join(str(p) for p in e.get("loc", [])[1:]), "type": e.get("type", "")}
                    for e in exc.errors()]
        return JSONResponse(status_code=422, content={"code": "validation_error", "details": problems})

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        host = request.url.netloc
        response.headers.setdefault("Content-Security-Policy", (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
            f"font-src 'self'; connect-src 'self' ws://{host} wss://{host}; object-src 'none'; base-uri 'self'; "
            "form-action 'self'; frame-ancestors 'none'"))
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/v1/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(auth_router.router)
    app.include_router(policy_router.router)
    app.include_router(users_router.router)
    app.include_router(roles_router.router)
    app.include_router(audit_router.router)
    app.include_router(email_router.router)
    app.include_router(assets_router.router)
    app.include_router(devices_router.router)
    app.include_router(telemetry_router.router)
    app.include_router(intel_router.router)
    app.include_router(incidents_router.router)

    if config.dev_loginless:
        try:
            from app import dev_loginless
        except ImportError:  # module removed from packages (DEV-005)
            pass
        else:
            dev_loginless.install(app)

    if FRONTEND_DIST.is_dir():
        built = FRONTEND_DIST / "static"
        if built.is_dir():
            app.mount("/static", StaticFiles(directory=built), name="static")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> FileResponse:
            candidate = (FRONTEND_DIST / path).resolve()
            if path and candidate.is_file() and FRONTEND_DIST in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(FRONTEND_DIST / "index.html")

    return app


def app_factory() -> FastAPI:
    """Used by `uvicorn app.main:app_factory --factory`."""
    return create_app()
