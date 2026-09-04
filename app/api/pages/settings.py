import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.alert import AlertConfig, NotificationChannel, SeverityThreshold
from models.project import Project
from services.auth import (
    api_key_default_expiry,
    create_api_key,
    list_api_keys,
    revoke_api_key,
)
from templating import templates

router = APIRouter(tags=["settings"], include_in_schema=False)


def _resolve_expiry(raw) -> datetime | None:
    """Map a ``ttl_days`` form/json value to an ``expires_at``.

    Empty/unset falls back to the configured default (forced rotation);
    ``0`` explicitly disables expiry; a positive integer sets a TTL in days.
    """
    if raw in (None, ""):
        return api_key_default_expiry()
    try:
        days = float(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="ttl_days must be an integer") from exc
    if days < 0 or not days.is_integer():
        raise HTTPException(status_code=400, detail="ttl_days must be a non-negative integer")
    if days == 0:
        return None
    return datetime.now(UTC) + timedelta(days=int(days))


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: AsyncSession = Depends(get_db)):
    projects = (await db.execute(select(Project).order_by(Project.name))).scalars().all()
    alerts = (
        (await db.execute(select(AlertConfig).order_by(AlertConfig.created_at.desc())))
        .scalars()
        .all()
    )
    api_keys = await list_api_keys(db)
    project_names = {str(project.id): project.name for project in projects}
    ctx = {
        "projects": projects,
        "alerts": alerts,
        "api_keys": api_keys,
        "project_names": project_names,
        "api_key_ttl_days": settings.api_key_ttl_days,
        "severity_thresholds": list(SeverityThreshold),
        "notification_channels": list(NotificationChannel),
    }
    return templates.TemplateResponse(request, "settings.html", ctx)


@router.post("/settings/api-keys", response_class=HTMLResponse)
async def create_api_key_web(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    user = getattr(request.state, "user", None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    if request.headers.get("content-type", "").startswith("application/json"):
        payload = await request.json()
        label = str(payload.get("label", ""))
        raw_ttl = payload.get("ttl_days", "")
    else:
        form = await request.form()
        label = str(form.get("label", ""))
        raw_ttl = form.get("ttl_days", "")

    key, raw = await create_api_key(
        db, uuid.UUID(user.id), label=label, expires_at=_resolve_expiry(raw_ttl)
    )
    await db.commit()

    if request.headers.get("content-type", "").startswith("application/json"):
        return JSONResponse(
            status_code=201,
            content={
                "id": str(key.id),
                "key": raw,
                "key_prefix": key.key_prefix,
                "label": key.label,
                "expires_at": key.expires_at.isoformat() if key.expires_at else None,
            },
        )

    api_keys = await list_api_keys(db)
    ctx = {
        "projects": [],
        "alerts": [],
        "api_keys": api_keys,
        "api_key_ttl_days": settings.api_key_ttl_days,
        "new_key": raw,
        "new_key_prefix": key.key_prefix,
    }
    return templates.TemplateResponse(request, "settings.html", ctx)


@router.delete("/settings/api-keys/{key_id}", status_code=204)
async def revoke_api_key_web(
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await revoke_api_key(db, key_id)
    await db.commit()
