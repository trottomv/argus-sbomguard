import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api import alerts, dashboard, projects, sboms, vulnerabilities
from config import settings
from services.grpc_server import start_grpc_server


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    grpc_server = await start_grpc_server()
    try:
        yield
    finally:
        await grpc_server.stop(5)


app = FastAPI(
    title="Argus SBOM Guard",
    version="0.1.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(projects.router)
app.include_router(sboms.router)
app.include_router(vulnerabilities.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "argus-sbomguard"}
