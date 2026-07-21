import json

import pytest


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "argus-sbomguard"


@pytest.mark.asyncio
async def test_create_project(client):
    resp = await client.post(
        "/api/v1/projects",
        json={"name": "test-service", "description": "A test project"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "test-service"
    assert "id" in data


@pytest.mark.asyncio
async def test_list_projects(client):
    await client.post("/api/v1/projects", json={"name": "s1"})
    await client.post("/api/v1/projects", json={"name": "s2"})

    resp = await client.get("/api/v1/projects")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["projects"]) >= 2


@pytest.mark.asyncio
async def test_create_duplicate_project(client):
    await client.post("/api/v1/projects", json={"name": "dup"})
    resp = await client.post("/api/v1/projects", json={"name": "dup"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_get_project(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "get-me"})
    pid = create_resp.json()["id"]

    resp = await client.get(f"/api/v1/projects/{pid}")
    assert resp.status_code == 200
    assert resp.json()["name"] == "get-me"


@pytest.mark.asyncio
async def test_get_project_not_found(client):
    resp = await client.get("/api/v1/projects/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


SAMPLE_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "components": [
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
        },
        {
            "type": "library",
            "name": "react",
            "version": "18.2.0",
            "purl": "pkg:npm/react@18.2.0",
        },
    ],
}


@pytest.mark.asyncio
async def test_upload_sbom(client):
    proj = await client.post("/api/v1/projects", json={"name": "sbom-test"})
    pid = proj.json()["id"]

    resp = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "version": "v1.0.0"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["format"] == "cyclonedx"
    assert data["dependency_count"] == 2


@pytest.mark.asyncio
async def test_active_vulnerabilities(client):
    resp = await client.get("/api/v1/vulnerabilities/active")
    assert resp.status_code == 200
    assert "vulnerabilities" in resp.json()


@pytest.mark.asyncio
async def test_vulnerability_summary(client):
    resp = await client.get("/api/v1/vulnerabilities/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "counts" in data
    assert "total" in data
