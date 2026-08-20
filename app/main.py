import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from api import auth, pages
from api.v1 import alerts, projects, sboms, services, vulnerabilities
from config import settings
from database import async_session_factory, engine
from logging_config import log_exception, setup_logging
from middleware import AuthMiddleware
from middleware.security_headers import SecurityHeadersMiddleware
from services.auth import seed_admin_user
from services.grpc_server import start_grpc_server
from services.otel import (
    init_tracing,
    instrument_fastapi,
    instrument_httpx,
    shutdown_tracing,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging(settings.log_level, settings.log_format)
    async with async_session_factory() as db:
        await seed_admin_user(db)
        await db.commit()

    grpc_server = await start_grpc_server()
    try:
        yield
    finally:
        await grpc_server.stop(5)
        shutdown_tracing()


app = FastAPI(
    title="Argus SBOM Guard",
    version=settings.app_version,
    lifespan=lifespan,
    openapi_url="/api/openapi.json",
    docs_url=None,
    redoc_url="/api/docs",
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuthMiddleware)


@app.exception_handler(Exception)
def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Log unhandled exceptions as structured events and return a generic 500.

    Product-agnostic error tracking: the exception (type, message, traceback)
    and the request context are emitted as a single structured ``event=exception``
    log line, which any log aggregator or error tracker can consume. The client
    only ever sees a generic ``Internal Server Error`` response — internals are
    never leaked. Registered for ``Exception``, so the handler is wired into
    Starlette's ``ServerErrorMiddleware`` and also catches errors raised by the
    middleware stack, not just by route handlers.

    Note: because this handler is the outermost catch-all, an ``HTTPException``
    raised by a *middleware* (rather than by a route or dependency, which are
    handled by ``ExceptionMiddleware``) would be converted into a generic 500.
    Keep middleware from raising ``HTTPException`` — return a response instead.
    """
    log_exception(exc, request=request)
    return PlainTextResponse("Internal Server Error", status_code=500)


# Instrument FastAPI and httpx at module load, so the middleware stack is
# patched before uvicorn builds it and the OpenTelemetry spans are captured.
# init_tracing() sets the global provider first (no-op when disabled), and each
# helper is itself a no-op when tracing is off. This wiring is exercised when
# main is imported by the test suite.
init_tracing()
instrument_fastapi(app)
instrument_httpx()

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> FileResponse:
    return FileResponse("static/favicon.ico")


app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(sboms.router)
app.include_router(services.router)
app.include_router(vulnerabilities.router)
app.include_router(alerts.router)
app.include_router(pages.dashboard.router)
app.include_router(pages.projects.router)
app.include_router(pages.vulnerabilities.router)
app.include_router(pages.sboms.router)
app.include_router(pages.settings.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "argus-sbomguard", "version": settings.app_version}


@app.get("/readyz")
async def readyz():
    checks: dict[str, str] = {}

    try:
        async with engine.connect() as conn:
            await asyncio.wait_for(
                conn.execute(text("SELECT 1")), settings.readiness_timeout_seconds
            )
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(settings.rabbitmq_host, settings.rabbitmq_port),
            settings.readiness_timeout_seconds,
        )
        writer.close()
        await writer.wait_closed()
        checks["rabbitmq"] = "ok"
    except Exception:
        checks["rabbitmq"] = "error"

    if all(status == "ok" for status in checks.values()):
        return {"status": "ok", "checks": checks}

    return JSONResponse(status_code=503, content={"status": "error", "checks": checks})
