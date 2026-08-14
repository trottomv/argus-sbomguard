import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from api import alerts, api_keys, auth, dashboard, projects, sboms, services, vulnerabilities
from config import settings
from database import async_session_factory, engine
from middleware import AuthMiddleware
from services.auth import seed_admin_user
from services.grpc_server import start_grpc_server


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    async with async_session_factory() as db:
        await seed_admin_user(db)
        await db.commit()

    grpc_server = await start_grpc_server()
    try:
        yield
    finally:
        await grpc_server.stop(5)


app = FastAPI(
    title="Argus SBOM Guard",
    version=settings.app_version,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(AuthMiddleware)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(sboms.router)
app.include_router(services.router)
app.include_router(vulnerabilities.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)
app.include_router(api_keys.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "argus-sbomguard", "version": settings.app_version}


@app.get("/readyz")
async def readyz():
    checks: dict[str, str] = {}

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"

    try:
        _, writer = await asyncio.open_connection(settings.rabbitmq_host, settings.rabbitmq_port)
        writer.close()
        await writer.wait_closed()
        checks["rabbitmq"] = "ok"
    except Exception:
        checks["rabbitmq"] = "error"

    if all(status == "ok" for status in checks.values()):
        return {"status": "ok", "checks": checks}

    return JSONResponse(status_code=503, content={"status": "error", "checks": checks})
