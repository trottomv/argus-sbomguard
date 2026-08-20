from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.auth import User
from services.auth import validate_api_key

# Declared so the OpenAPI schema advertises the auth requirement: the docs UIs
# show an "Authorize" button and the X-API-Key header. auto_error=False keeps
# session-cookie auth (web UI) working — the dependency below raises its own 401.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def api_key_required(
    request: Request,
    _api_key: str | None = Security(api_key_header),
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
