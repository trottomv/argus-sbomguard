from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

CSP_DIRECTIVES = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

# FastAPI's Swagger UI and ReDoc pages need inline scripts, blob: workers and
# resources from third-party hosts (jsDelivr, Google Fonts, cdn.redoc.ly) that
# the strict CSP above forbids. These public documentation pages are excluded
# from the CSP; every other page keeps the strict policy.
DOCS_PATHS = {"/api/docs", "/api/redoc"}

PERMISSIONS_POLICY = (
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
    "magnetometer=(), gyroscope=(), accelerometer=(), browsing-topics=()"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Set security and caching headers on responses.

    Page-oriented policies (CSP, X-Frame-Options, Referrer-Policy,
    Permissions-Policy) are only sent on ``text/html`` responses. The CSP
    forbids inline scripts, event-handler attributes and ``unsafe-eval``;
    Alpine runs the CSP-friendly build with its components registered via
    ``Alpine.data()``. The API docs pages (``/api/docs``, ``/api/redoc``) are
    excluded from the CSP — FastAPI loads their assets from third-party CDNs and
    they need inline scripts and blob: workers — but keep the other security
    headers. ``X-Content-Type-Options: nosniff`` is set on every response.

    Caching: the private area (authenticated pages and JSON API responses)
    is ``Cache-Control: no-store`` so sensitive data is never cached; static
    assets are ``public`` with a bounded ``max-age`` (they are revalidated via
    ETag and are not content-hashed, so ``immutable`` would risk stale deploys).
    The ``/favicon.ico`` route is cached like static assets so the browser's
    automatic favicon probe is not re-downloaded on every page load.
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.url.path.startswith("/static") or request.url.path == "/favicon.ico":
            response.headers["Cache-Control"] = "public, max-age=604800"
        else:
            response.headers["Cache-Control"] = "no-store"
        content_type = response.headers.get("content-type", "")
        if content_type.lower().startswith("text/html"):
            if request.url.path not in DOCS_PATHS:
                response.headers["Content-Security-Policy"] = CSP_DIRECTIVES
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = PERMISSIONS_POLICY
        return response
