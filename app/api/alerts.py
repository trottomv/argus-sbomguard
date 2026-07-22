import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.api_key import api_key_required
from models.alert import AlertConfig
from models.project import Project

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"], dependencies=[Depends(api_key_required)])


class AlertConfigCreate(BaseModel):
    project_id: str
    severity_threshold: str = "high"
    notification_type: str = "slack"
    config: dict = {}
    enabled: bool = True


@router.get("")
async def list_alerts(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AlertConfig).order_by(AlertConfig.created_at.desc()))
    alerts = result.scalars().all()
    return {
        "alerts": [
            {
                "id": str(a.id),
                "project_id": str(a.project_id),
                "severity_threshold": a.severity_threshold,
                "notification_type": a.notification_type,
                "enabled": a.enabled,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ]
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
