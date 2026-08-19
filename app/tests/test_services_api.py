import json

import pytest

from tests.helpers import SAMPLE_CYCLONEDX


@pytest.mark.asyncio
async def test_delete_service_not_found(client):
    resp = await client.delete("/api/v1/services/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_service_with_sboms(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "svc-conflict"})
    pid = create_resp.json()["id"]

    await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "service_name": "test-svc", "version": "v1"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )

    svc_resp = await client.get(f"/api/v1/services?project_id={pid}")
    assert svc_resp.status_code == 200
    services = svc_resp.json()
    assert len(services) == 1
    sid = services[0]["id"]

    del_resp = await client.delete(f"/api/v1/services/{sid}")
    assert del_resp.status_code == 409


@pytest.mark.asyncio
async def test_delete_service_empty(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "svc-empty"})
    pid = create_resp.json()["id"]

    await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "service_name": "to-remove", "version": "v1"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )

    svc_resp = await client.get(f"/api/v1/services?project_id={pid}")
    services = svc_resp.json()
    assert len(services) == 1
    sid = services[0]["id"]

    sboms_resp = await client.get(f"/api/v1/projects/{pid}/history")
    sbid = sboms_resp.json()["items"][0]["id"]

    await client.delete(f"/api/v1/sboms/{sbid}")

    del_resp = await client.delete(f"/api/v1/services/{sid}")
    assert del_resp.status_code == 204

    svc_resp2 = await client.get(f"/api/v1/services?project_id={pid}")
    assert len(svc_resp2.json()) == 0
