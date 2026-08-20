import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.constants import API_V1_PREFIX
from api.v1.schemas import ServiceResponse
from database import get_db
from middleware.api_key import api_key_required
from models.sbom import SBOM
from models.service import Service

router = APIRouter(
    prefix=f"{API_V1_PREFIX}/services",
    tags=["services"],
    dependencies=[Depends(api_key_required)],
)


@router.get("", response_model=list[ServiceResponse])
async def list_services(
    project_id: uuid.UUID = Query(...),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Service).where(Service.project_id == project_id).order_by(Service.name)
    )
    services = result.scalars().all()
    return [ServiceResponse.model_validate(service) for service in services]


@router.delete("/{service_id}", status_code=204)
async def delete_service(service_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Service).where(Service.id == service_id))
    service = result.scalar_one_or_none()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")

    sbom_count = await db.execute(
        select(func.count()).select_from(SBOM).where(SBOM.service_id == service_id)
    )
    count = sbom_count.scalar() or 0
    if count > 0:
        raise HTTPException(status_code=409, detail=f"Cannot delete service with {count} SBOM(s)")

    await db.delete(service)
    await db.commit()
