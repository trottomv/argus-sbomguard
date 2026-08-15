from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

CSP_DIRECTIVES = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforce a strict Content-Security-Policy over every response.

    Inline scripts and event-handler attributes are not allowed
    (no ``unsafe-inline``). Alpine.js evaluates its declarative attributes
    via ``new Function``, which requires ``unsafe-eval``; dropping that
    entirely would need the Alpine CSP build.
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP_DIRECTIVES
        return response
