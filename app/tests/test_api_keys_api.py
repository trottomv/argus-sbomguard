import pytest


@pytest.mark.asyncio
async def test_list_api_keys(client):
    resp = await client.get("/api/v1/api-keys")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_create_api_key(client):
    resp = await client.post("/api/v1/api-keys", json={"label": "ci"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["key"]
    assert data["label"] == "ci"
    assert data["key_prefix"]


@pytest.mark.asyncio
async def test_revoke_api_key(client):
    created = await client.post("/api/v1/api-keys", json={})
    key_id = created.json()["id"]
    resp = await client.delete(f"/api/v1/api-keys/{key_id}")
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_revoke_api_key_not_found(client):
    resp = await client.delete("/api/v1/api-keys/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404
