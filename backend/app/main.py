import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    yield


app = FastAPI(
    title="Argus SBOM Guard",
    version="0.1.0",
    lifespan=lifespan,
)

templates = Jinja2Templates(directory="app/templates")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

from app.api import alerts, dashboard, projects, sboms, vulnerabilities

app.include_router(projects.router)
app.include_router(sboms.router)
app.include_router(vulnerabilities.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "argus-sbomguard"}
