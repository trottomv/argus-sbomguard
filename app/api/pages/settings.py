import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.alert import AlertConfig, NotificationChannel, SeverityThreshold
from models.project import Project
from services.auth import create_api_key, list_api_keys, revoke_api_key
from templating import templates

router = APIRouter(tags=["settings"], include_in_schema=False)


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
    else:
        form = await request.form()
        label = str(form.get("label", ""))

    key, raw = await create_api_key(db, uuid.UUID(user.id), label=label)
    await db.commit()

    if request.headers.get("content-type", "").startswith("application/json"):
        return JSONResponse(
            status_code=201,
            content={
                "id": str(key.id),
                "key": raw,
                "key_prefix": key.key_prefix,
                "label": key.label,
            },
        )

    api_keys = await list_api_keys(db)
    ctx = {
        "projects": [],
        "alerts": [],
        "api_keys": api_keys,
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
