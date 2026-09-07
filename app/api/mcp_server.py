"""FastAPI wiring for the read-only MCP endpoint.

``services.mcp_server`` holds the MCP server itself: the tool functions, the
``build_mcp_server`` factory and ``mcp_transport_security``. This module is the
HTTP composition root for that server. It instantiates the server, mounts its
Streamable HTTP transport configured with ``mcp_transport_security``, wraps the
transport in ``MCPAuthMiddleware`` (API-key bearer auth) and guards everything
behind ``_MCPGate`` — an ASGI gate that returns 404 while ``MCP_ENABLED`` is off
and otherwise rewrites the request path to ``/`` before forwarding, because the
transport's internal routes expect a scope path of ``/``.

The gate is registered on ``router`` at both slash variants so clients need not
rely on redirects. ``include_router`` copies plain Starlette routes verbatim
(ignoring any router ``prefix``), so the mount paths carry the full API prefix
here. ``mcp_server`` is exported so ``main.py`` can drive its session manager
from the application lifespan.
"""

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from api.constants import API_V1_PREFIX
from config import settings
from middleware.mcp_auth import MCPAuthMiddleware
from services.mcp_server import build_mcp_server, mcp_transport_security

mcp_server = build_mcp_server()
mcp_transport_app = mcp_server.streamable_http_app(
    streamable_http_path="/",
    transport_security=mcp_transport_security(),
)

mcp_authed_app = MCPAuthMiddleware(mcp_transport_app)


class _MCPGate:
    """ASGI gate that exposes the MCP transport under the API prefix."""

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await mcp_authed_app(scope, receive, send)
            return
        if not settings.mcp_enabled:
            response = PlainTextResponse("Not Found", status_code=404)
            await response(scope, receive, send)
            return
        rewritten = dict(scope)
        rewritten["path"] = "/"
        rewritten["raw_path"] = b"/"
        await mcp_authed_app(rewritten, receive, send)


mcp_gate = _MCPGate()

router = APIRouter(tags=["mcp"], include_in_schema=False)

router.add_route(
    f"{API_V1_PREFIX}/mcp", mcp_gate, methods=["GET", "POST", "DELETE"], include_in_schema=False
)
router.add_route(
    f"{API_V1_PREFIX}/mcp/", mcp_gate, methods=["GET", "POST", "DELETE"], include_in_schema=False
)
