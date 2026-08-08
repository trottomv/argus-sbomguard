import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.schemas import ApiKeyCreate, ApiKeyCreatedResponse, ApiKeyResponse
from database import get_db
from middleware.api_key import api_key_required
from services.auth import create_api_key, list_api_keys, revoke_api_key

router = APIRouter(prefix="/api/v1/api-keys", tags=["api-keys"])


@router.get("", response_model=list[ApiKeyResponse])
async def list_keys(
    db: AsyncSession = Depends(get_db),
    _user=Depends(api_key_required),
):
    keys = await list_api_keys(db)
    return [ApiKeyResponse.model_validate(k) for k in keys]


@router.post("", status_code=201, response_model=ApiKeyCreatedResponse)
async def create_key(
    data: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
    _user=Depends(api_key_required),
):
    key, raw = await create_api_key(db, uuid.UUID(str(_user.id)), label=data.label)
    await db.commit()

    return ApiKeyCreatedResponse(
        id=key.id,
        key=raw,
        key_prefix=key.key_prefix,
        label=key.label,
        created_at=key.created_at,
    )


@router.delete("/{key_id}", status_code=204)
async def revoke_key(
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user=Depends(api_key_required),
):
    deleted = await revoke_api_key(db, key_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="API key not found")
    await db.commit()
