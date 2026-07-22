import logging
import uuid

from fastapi import Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings
from database import get_db
from services.auth import get_user_by_id

logger = logging.getLogger(__name__)

PUBLIC_PATHS = {"/login", "/login/verify", "/health", "/favicon.ico"}

_SESSION_MAX_AGE = settings.session_max_age_hours * 3600

_session_serializer = URLSafeTimedSerializer(settings.secret_key, salt="argus-session")


def _get_user_id_from_cookie(request: Request) -> str | None:
    cookie = request.cookies.get("argus_session")
    if not cookie:
        return None
    try:
        data = _session_serializer.loads(cookie, max_age=_SESSION_MAX_AGE)
        return data.get("user_id")
    except BadSignature:
        return None


def set_session_cookie(response, user_id: str):
    cookie = _session_serializer.dumps({"user_id": user_id})
    response.set_cookie(
        "argus_session",
        cookie,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=_SESSION_MAX_AGE,
    )


def clear_session_cookie(response):
    response.delete_cookie("argus_session")


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/") or "/"

        user_id = _get_user_id_from_cookie(request)

        if user_id:
            db_gen = get_db()
            async for db in db_gen:
                try:
                    user = await get_user_by_id(db, uuid.UUID(user_id))
                    if user:
                        request.state.user = user
                finally:
                    break

        if (
            path in PUBLIC_PATHS
            or path.startswith("/login")
            or path.startswith("/static")
            or path.startswith("/api/")
        ):
            return await call_next(request)

        if not user_id:
            return RedirectResponse(url="/login", status_code=302)

        return await call_next(request)
