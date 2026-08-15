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

PERMISSIONS_POLICY = (
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
    "magnetometer=(), gyroscope=(), accelerometer=(), browsing-topics=()"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Set security and caching headers on responses.

    Page-oriented policies (CSP, X-Frame-Options, Referrer-Policy,
    Permissions-Policy) are only sent on ``text/html`` responses. The CSP
    forbids inline scripts and event-handler attributes (no ``unsafe-inline``);
    Alpine.js evaluates its declarative attributes via ``new Function``, which
    requires ``unsafe-eval`` (see the #83 follow-up for the Alpine CSP build).
    ``X-Content-Type-Options: nosniff`` is set on every response.

    Caching: the private area (authenticated pages and JSON API responses)
    is ``Cache-Control: no-store`` so sensitive data is never cached; static
    assets are ``public`` with a bounded ``max-age`` (they are revalidated via
    ETag and are not content-hashed, so ``immutable`` would risk stale deploys).
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.url.path.startswith("/static"):
            response.headers["Cache-Control"] = "public, max-age=604800"
        else:
            response.headers["Cache-Control"] = "no-store"
        content_type = response.headers.get("content-type", "")
        if content_type.lower().startswith("text/html"):
            response.headers["Content-Security-Policy"] = CSP_DIRECTIVES
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = PERMISSIONS_POLICY
        return response
