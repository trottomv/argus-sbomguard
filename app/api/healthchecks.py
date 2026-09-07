import asyncio

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from config import settings
from database import engine

router = APIRouter(tags=["health"])


def _build_provenance() -> dict[str, str]:
    """Build provenance (repository, commit, environment) metadata."""
    return {
        "service": "argus-sbomguard",
        "version": settings.app_version,
        "git_sha": settings.build_git_sha,
        "build_date": settings.build_date,
        "source_url": settings.build_source_url,
        "build_env": settings.build_env,
        "environment": settings.app_env,
    }


@router.get("/healthz")
async def healthz():
    return {"status": "ok", **_build_provenance()}


@router.get("/version")
async def version():
    return _build_provenance()


@router.get("/readyz")
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
