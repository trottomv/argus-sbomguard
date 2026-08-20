import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.constants import API_V1_PREFIX
from api.v1.schemas import (
    ActionResponse,
    AlertConfigCreate,
    AlertConfigResponse,
    AlertConfigUpdate,
    PageResponse,
)
from database import get_db
from middleware.api_key import api_key_required
from models.alert import AlertConfig
from models.project import Project
from services.pagination import ALERT_PER_PAGE, Page, paginate

router = APIRouter(
    prefix=f"{API_V1_PREFIX}/alert-rules",
    tags=["alert-rules"],
    dependencies=[Depends(api_key_required)],
)


@router.get("", response_model=PageResponse[AlertConfigResponse])
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(ALERT_PER_PAGE, ge=1, le=200),
):
    query = select(AlertConfig).order_by(AlertConfig.created_at.desc())
    pg: Page = await paginate(db, query, page=page, per_page=per_page)
    return PageResponse[AlertConfigResponse](
        items=[AlertConfigResponse.model_validate(alert) for alert in pg.items],
        total=pg.total,
        page=pg.page,
        per_page=pg.per_page,
        total_pages=pg.total_pages,
        has_more=pg.has_more,
    )


@router.post("", status_code=201, response_model=AlertConfigResponse)
async def create_alert(data: AlertConfigCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == uuid.UUID(data.project_id)))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    alert = AlertConfig(
        project_id=uuid.UUID(data.project_id),
        severity_threshold=data.severity_threshold,
        notification_type=data.notification_type,
        config=data.config,
        enabled=data.enabled,
    )
    db.add(alert)
    await db.flush()
    return AlertConfigResponse.model_validate(alert)


@router.delete("/{alert_id}", response_model=ActionResponse)
async def delete_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AlertConfig).where(AlertConfig.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await db.delete(alert)
    return ActionResponse(status="deleted")


@router.patch("/{alert_id}", response_model=ActionResponse)
async def update_alert(
    alert_id: uuid.UUID, data: AlertConfigUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(AlertConfig).where(AlertConfig.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if data.project_id is not None:
        result = await db.execute(select(Project).where(Project.id == uuid.UUID(data.project_id)))
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Project not found")
        alert.project_id = uuid.UUID(data.project_id)
    if data.severity_threshold is not None:
        alert.severity_threshold = data.severity_threshold
    if data.notification_type is not None:
        alert.notification_type = data.notification_type
    if data.enabled is not None:
        alert.enabled = data.enabled

    await db.commit()
    return ActionResponse(status="updated")
