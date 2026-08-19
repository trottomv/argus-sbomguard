import pytest
from sqlalchemy import select
from starlette.requests import Request

from api.pages.settings import create_api_key_web
from models.auth import ApiKey


@pytest.mark.asyncio
async def test_settings_page(client):
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_create_api_key_web(client):
    resp = await client.post("/settings/api-keys", data={"label": "web"})
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_create_api_key_web_defensive_redirect_without_user(db_session):
    # The auth middleware already redirects anonymous users, but the handler
    # keeps a defensive guard: invoking it without an authenticated session
    # must redirect to /login instead of creating a key.
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/settings/api-keys",
        "query_string": b"",
        "headers": [],
        "state": {},
    }
    request = Request(scope)
    resp = await create_api_key_web(request, db=db_session)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_revoke_api_key_web(client, db_session):
    await client.post("/settings/api-keys", data={"label": "revoke"})
    key = (
        (await db_session.execute(select(ApiKey).order_by(ApiKey.created_at.desc())))
        .scalars()
        .first()
    )
    assert key is not None

    resp = await client.delete(f"/settings/api-keys/{key.id}")
    assert resp.status_code == 204
