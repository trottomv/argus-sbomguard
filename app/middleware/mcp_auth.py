"""ASGI auth wrapper for the read-only MCP endpoint.

MCP clients (opencode, Claude Code, ...) send ``Authorization: Bearer
<api-key>`` on every request; validating the header scheme instead of relying
on the client-side OAuth discovery prevents the auto-detection flow entirely.
Session cookies are deliberately ignored: agent access is scoped to API keys,
which can be revoked independently of human sessions.
"""

import json
from typing import Any

from database import async_session_factory
from services.auth import authenticate_api_key

_JSON_CONTENT_TYPE = b"application/json"


async def _unauthorized(send: Any, detail: str, *, expired: bool) -> None:
    """Send a 401 response with a Bearer challenge."""
    header = b'Bearer error="invalid_token", error_description="expired"' if expired else b"Bearer"
    body = json.dumps({"detail": detail}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", _JSON_CONTENT_TYPE),
                (b"www-authenticate", header),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class MCPAuthMiddleware:
    """Require a valid API key for every request reaching the MCP app."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        authorization = ""
        for raw_name, raw_value in scope.get("headers", []):
            if raw_name.lower() == b"authorization":
                authorization = raw_value.decode("latin-1")
                break

        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            await _unauthorized(send, "Bearer token required", expired=False)
            return

        async with async_session_factory() as db:
            result = await authenticate_api_key(db, token)
            await db.commit()

        if result.expired:
            await _unauthorized(send, "API key expired", expired=True)
            return
        if not result.valid:
            await _unauthorized(send, "Invalid API key", expired=False)
            return

        await self.app(scope, receive, send)
