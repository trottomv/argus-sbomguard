import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.api_key import api_key_required
from models.alert import AlertConfig
from models.project import Project
from services.pagination import ALERT_PER_PAGE, Page, paginate

router = APIRouter(
    prefix="/api/v1/alerts", tags=["alerts"], dependencies=[Depends(api_key_required)]
)


class AlertConfigCreate(BaseModel):
    project_id: str
    severity_threshold: str = "high"
    notification_type: str = "slack"
    config: dict = {}
    enabled: bool = True


class AlertConfigUpdate(BaseModel):
    project_id: str | None = None
    severity_threshold: str | None = None
    notification_type: str | None = None
    enabled: bool | None = None


@router.get("")
async def list_alerts(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(ALERT_PER_PAGE, ge=1, le=200),
):
    query = select(AlertConfig).order_by(AlertConfig.created_at.desc())
    pg: Page = await paginate(db, query, page=page, per_page=per_page)
    return {
        "items": [
            {
                "id": str(a.id),
                "project_id": str(a.project_id),
                "severity_threshold": a.severity_threshold,
                "notification_type": a.notification_type,
                "enabled": a.enabled,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in pg.items
        ],
        "total": pg.total,
        "page": pg.page,
        "per_page": pg.per_page,
        "total_pages": pg.total_pages,
    }


@router.post("", status_code=201)
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
    return {
        "id": str(alert.id),
        "project_id": str(alert.project_id),
        "severity_threshold": alert.severity_threshold,
        "notification_type": alert.notification_type,
        "enabled": alert.enabled,
    }


@router.delete("/{alert_id}")
async def delete_alert(alert_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AlertConfig).where(AlertConfig.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await db.delete(alert)
    return {"status": "deleted"}


@router.patch("/{alert_id}")
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
    return {"status": "updated"}
