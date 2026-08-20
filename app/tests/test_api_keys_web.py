import pytest


@pytest.mark.asyncio
async def test_create_api_key_web_json(client):
    resp = await client.post(
        "/settings/api-keys",
        json={"label": "ci"},
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["key"].startswith("argus_")
    assert data["label"] == "ci"
    assert data["key_prefix"]


@pytest.mark.asyncio
async def test_revoke_api_key_web(client, db_session):
    created = await client.post("/settings/api-keys", json={})
    key_id = created.json()["id"]
    resp = await client.delete(f"/settings/api-keys/{key_id}")
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_api_keys_rest_endpoints_removed(client):
    resp = await client.get("/api/v1/api-keys")
    assert resp.status_code == 404
    resp = await client.post("/api/v1/api-keys", json={"label": "x"})
    assert resp.status_code == 404
