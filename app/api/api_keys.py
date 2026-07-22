import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.api_key import api_key_required
from services.auth import create_api_key, list_api_keys, revoke_api_key

router = APIRouter(prefix="/api/v1/api-keys", tags=["api-keys"])


@router.get("")
async def list_keys(
    db: AsyncSession = Depends(get_db),
    _user=Depends(api_key_required),
):
    keys = await list_api_keys(db)
    return [
        {
            "id": str(k.id),
            "key_prefix": k.key_prefix,
            "label": k.label,
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
        }
        for k in keys
    ]


@router.post("", status_code=201)
async def create_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _user=Depends(api_key_required),
):
    body = await request.json()
    label = body.get("label", "")

    key, raw = await create_api_key(db, _user.id, label=label)
    await db.commit()

    return {
        "id": str(key.id),
        "key": raw,
        "key_prefix": key.key_prefix,
        "label": key.label,
        "created_at": key.created_at.isoformat() if key.created_at else None,
    }


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
