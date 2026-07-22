from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.user import User
from services.auth import validate_api_key


async def api_key_required(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    session_user = getattr(request.state, "user", None)
    if session_user is not None:
        return session_user

    raw_key = request.headers.get("X-API-Key", "")
    if not raw_key:
        raise HTTPException(status_code=401, detail="API key required")

    user = await validate_api_key(db, raw_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return user
