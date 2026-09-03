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

# FastAPI's ReDoc page needs inline scripts, blob: workers and resources from
# third-party hosts (jsDelivr, Google Fonts, cdn.redoc.ly) that the strict CSP
# above forbids. This public documentation page is excluded from the CSP; every
# other page keeps the strict policy.
DOCS_PATHS = {"/api/docs"}

PERMISSIONS_POLICY = (
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
    "magnetometer=(), gyroscope=(), accelerometer=(), browsing-topics=()"
)

# Cache-control max-age headers for public and private pages.
CACHE_CONTROL_PUBLIC_PATH_PREFIXES = (
    "/static",
    "/favicon.ico",
)
CACHE_CONTROL_PUBLIC_MAX_AGE_SECONDS: int = 604800  # 7 days
CACHE_CONTROL_PRIVATE_MAX_AGE_SECONDS: int = 0  # no caching for private pages


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Set security and caching headers on responses.

    Page-oriented policies (CSP, X-Frame-Options, Referrer-Policy,
    Permissions-Policy) are only sent on ``text/html`` responses. The CSP
    forbids inline scripts, event-handler attributes and ``unsafe-eval``;
    Alpine runs the CSP-friendly build with its components registered via
    ``Alpine.data()``. The API docs page (``/api/docs``, which serves ReDoc)
    is excluded from the CSP — FastAPI loads its assets from third-party CDNs
    and it needs inline scripts and blob: workers — but keeps the other
    security headers. ``X-Content-Type-Options: nosniff`` is set on every
    response.

    Caching: the private area (authenticated pages and JSON API responses)
    is never cached — ``private, no-cache, no-store, must-revalidate,
    max-age=0`` keeps sensitive data out of every cache; static assets are
    ``public`` with a bounded ``max-age`` (``CACHE_CONTROL_PUBLIC_MAX_AGE_SECONDS``,
    default 604800 seconds) and are revalidated via ETag — they are not
    content-hashed, so ``immutable`` would risk stale deploys. The
    ``/favicon.ico`` route is cached like static assets so the browser's
    automatic favicon probe is not re-downloaded on every page load.
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        if any(
            request.url.path.startswith(prefix) for prefix in CACHE_CONTROL_PUBLIC_PATH_PREFIXES
        ):
            response.headers["Cache-Control"] = (
                f"public, max-age={CACHE_CONTROL_PUBLIC_MAX_AGE_SECONDS}"
            )
        else:
            response.headers["Cache-Control"] = (
                "private, no-cache, no-store, must-revalidate, "
                f"max-age={CACHE_CONTROL_PRIVATE_MAX_AGE_SECONDS}"
            )
        content_type = response.headers.get("content-type", "")
        if content_type.lower().startswith("text/html"):
            if request.url.path not in DOCS_PATHS:
                response.headers["Content-Security-Policy"] = CSP_DIRECTIVES
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = PERMISSIONS_POLICY
        return response
