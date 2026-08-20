"""Tests for the auth session middleware."""

import re
from pathlib import Path

import pytest
from starlette.requests import Request
from starlette.responses import Response

from main import app
from middleware.auth import _get_user_from_cookie, clear_session_cookie, set_session_cookie

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


def _request(cookies: dict[str, str] | None = None) -> Request:
    cookie_header = "; ".join(f"{k}={v}" for k, v in (cookies or {}).items())
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/projects",
        "query_string": b"",
        "headers": [(b"cookie", cookie_header.encode())] if cookie_header else [],
        "state": {},
    }
    return Request(scope)


def test_get_user_from_cookie_none_when_missing():
    assert _get_user_from_cookie(_request()) is None


def test_get_user_from_cookie_none_when_invalid():
    assert _get_user_from_cookie(_request({"argus_session": "not-a-valid-cookie"})) is None


def test_get_user_from_cookie_valid():
    response = Response()
    set_session_cookie(response, "user-123", email="u@example.com")
    cookie = response.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    user = _get_user_from_cookie(_request({"argus_session": cookie}))
    assert user is not None
    assert user.id == "user-123"
    assert user.email == "u@example.com"


def test_clear_session_cookie():
    response = Response()
    set_session_cookie(response, "user-123")
    clear_session_cookie(response)
    set_cookies = response.headers.getlist("set-cookie")
    assert any("argus_session=" in c and "Max-Age=0" in c for c in set_cookies)


@pytest.mark.asyncio
async def test_middleware_redirects_anonymous_html_requests(client):
    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as anon:
        resp = await anon.get("/projects")
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_middleware_redirects_htmx_requests_with_header(client):
    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as anon:
        resp = await anon.get("/projects", headers={"HX-Request": "true"})
        assert resp.status_code == 302
        assert resp.headers["HX-Redirect"] == "/login"


@pytest.mark.asyncio
async def test_middleware_allows_public_paths(client):
    for path in ("/healthz", "/readyz"):
        resp = await client.get(path)
        assert resp.status_code in (200, 503)


@pytest.mark.asyncio
async def test_security_headers_present_on_pages(client):
    resp = await client.get("/login")
    assert resp.status_code == 200
    csp = resp.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "script-src 'self' 'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
    assert "fonts.googleapis.com" not in csp
    assert "fonts.gstatic.com" not in csp
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "geolocation=()" in resp.headers["permissions-policy"]
    assert resp.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_docs_pages_skip_csp(client):
    resp = await client.get("/api/docs")
    assert resp.status_code == 200
    assert "content-security-policy" not in resp.headers
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"


@pytest.mark.asyncio
async def test_static_assets_served_locally(client):
    for path in (
        "/favicon.ico",
        "/static/favicon.ico",
        "/static/js/htmx.min.js",
        "/static/js/alpine-csp.min.js",
        "/static/js/alpine-components.js",
        "/static/js/chart.umd.min.js",
        "/static/js/app.js",
        "/static/js/dashboard.js",
        "/static/fonts/InterVariable.woff2",
        "/static/fonts/InterVariable-Italic.woff2",
    ):
        resp = await client.get(path)
        assert resp.status_code == 200
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["cache-control"] == "public, max-age=604800"
        assert "content-security-policy" not in resp.headers
        assert "x-frame-options" not in resp.headers
        assert "referrer-policy" not in resp.headers
        assert "permissions-policy" not in resp.headers


@pytest.mark.asyncio
async def test_json_api_gets_only_nosniff(client):
    resp = await client.get("/api/v1/projects")
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cache-control"] == "no-store"
    assert "content-security-policy" not in resp.headers
    assert "x-frame-options" not in resp.headers
    assert "referrer-policy" not in resp.headers
    assert "permissions-policy" not in resp.headers


_ON_HANDLER = re.compile(
    r"\bon(?:click|dblclick|mousedown|mouseup|mouseover|mouseout|mousemove|mouseenter|mouseleave|"
    r"change|input|submit|focus|blur|load|error|keydown|keyup|keypress|"
    r"resize|scroll|wheel|paste|copy|cut|contextmenu|drag|drop|touchstart|touchend)\s*=",
    re.IGNORECASE,
)

_SCRIPT_OPEN = re.compile(r"<script\b[^>]*>", re.IGNORECASE)


def _template_files():
    return sorted(TEMPLATES_DIR.rglob("*.html"))


def test_templates_have_no_inline_event_handlers():
    offenders = [
        f"{path.relative_to(TEMPLATES_DIR)}:{line_no}"
        for path in _template_files()
        for line_no, line in enumerate(path.read_text().splitlines(), 1)
        if _ON_HANDLER.search(line)
    ]
    assert not offenders, offenders


def test_templates_have_no_inline_executable_scripts():
    offenders = [
        f"{path.relative_to(TEMPLATES_DIR)}:{line_no}: {match}"
        for path in _template_files()
        for line_no, line in enumerate(path.read_text().splitlines(), 1)
        for match in _SCRIPT_OPEN.findall(line)
        if "src=" not in match.lower() and "application/json" not in match.lower()
    ]
    assert not offenders, offenders
