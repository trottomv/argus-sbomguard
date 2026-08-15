"""Tests for the auth session middleware."""

import pytest
from starlette.requests import Request
from starlette.responses import Response

from main import app
from middleware.auth import _get_user_from_cookie, clear_session_cookie, set_session_cookie


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
    assert "'unsafe-eval'" in csp


@pytest.mark.asyncio
async def test_static_js_served_locally(client):
    for path in (
        "/static/js/htmx.min.js",
        "/static/js/alpine.min.js",
        "/static/js/chart.umd.min.js",
        "/static/js/app.js",
        "/static/js/dashboard.js",
    ):
        resp = await client.get(path)
        assert resp.status_code == 200
        assert resp.headers["content-security-policy"]


@pytest.mark.asyncio
async def test_csp_applied_to_api_responses(client):
    resp = await client.get("/api/v1/projects")
    assert resp.status_code == 200
    assert "content-security-policy" in resp.headers
