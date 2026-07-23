import logging
from dataclasses import dataclass

from fastapi import Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings

logger = logging.getLogger(__name__)

PUBLIC_PATHS = {"/login", "/login/verify", "/health", "/favicon.ico"}

_SESSION_MAX_AGE = settings.session_max_age_hours * 3600

_session_serializer = URLSafeTimedSerializer(settings.secret_key, salt="argus-session")


@dataclass
class SessionUser:
    id: str
    email: str


def _get_user_from_cookie(request: Request) -> SessionUser | None:
    cookie = request.cookies.get("argus_session")
    if not cookie:
        return None
    try:
        data = _session_serializer.loads(cookie, max_age=_SESSION_MAX_AGE)
        return SessionUser(id=data["user_id"], email=data.get("email", ""))
    except BadSignature:
        return None


def set_session_cookie(response, user_id: str, email: str = ""):
    cookie = _session_serializer.dumps({"user_id": user_id, "email": email})
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

        session_user = _get_user_from_cookie(request)
        if session_user:
            request.state.user = session_user

        request.state.app_version = settings.app_version

        if (
            path in PUBLIC_PATHS
            or path.startswith("/login")
            or path.startswith("/static")
            or path.startswith("/api/")
        ):
            return await call_next(request)

        if not session_user:
            response = RedirectResponse(url="/login", status_code=302)
            if request.headers.get("HX-Request"):
                response.headers["HX-Redirect"] = "/login"
            return response

        return await call_next(request)
