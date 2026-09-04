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
async def test_create_api_key_web_with_ttl_days(client, db_session):
    resp = await client.post("/settings/api-keys", json={"label": "ttl30", "ttl_days": 30})
    assert resp.status_code == 201
    data = resp.json()
    assert data["expires_at"] is not None

    stored = (await db_session.execute(select(ApiKey).where(ApiKey.label == "ttl30"))).scalar_one()
    assert stored.expires_at is not None


@pytest.mark.asyncio
async def test_create_api_key_web_with_ttl_zero_no_expiry(client, db_session):
    resp = await client.post("/settings/api-keys", json={"label": "never", "ttl_days": 0})
    assert resp.status_code == 201
    assert resp.json()["expires_at"] is None

    stored = (await db_session.execute(select(ApiKey).where(ApiKey.label == "never"))).scalar_one()
    assert stored.expires_at is None


@pytest.mark.asyncio
async def test_create_api_key_web_invalid_ttl_rejected(client):
    resp = await client.post("/settings/api-keys", json={"label": "bad", "ttl_days": "abc"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_api_key_web_negative_ttl_rejected(client):
    resp = await client.post("/settings/api-keys", json={"label": "neg", "ttl_days": -1})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_api_key_web_fractional_ttl_rejected(client):
    resp = await client.post("/settings/api-keys", json={"label": "frac", "ttl_days": 30.5})
    assert resp.status_code == 400


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
