import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api import alerts, api_keys, auth, dashboard, projects, sboms, services, vulnerabilities
from config import settings
from database import async_session_factory
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


@app.get("/health")
async def health():
    return {"status": "ok", "service": "argus-sbomguard"}
