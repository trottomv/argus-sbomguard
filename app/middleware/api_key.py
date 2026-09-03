from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.auth import User
from services.auth import authenticate_api_key

# Declared so the OpenAPI schema advertises the auth requirement: the docs UIs
# show an "Authorize" button for the HTTPBearer scheme. auto_error=False keeps
# session-cookie auth (web UI) working — the dependency below raises its own 401.
bearer_scheme = HTTPBearer(auto_error=False)


async def api_key_required(
    request: Request,
    _credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    session_user = getattr(request.state, "user", None)
    if session_user is not None:
        return session_user

    auth = request.headers.get("Authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=401,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await authenticate_api_key(db, token)
    if result.expired:
        raise HTTPException(
            status_code=401,
            detail="API key expired",
            headers={
                "WWW-Authenticate": 'Bearer error="invalid_token", error_description="expired"'
            },
        )
    if not result.valid:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return result.user
