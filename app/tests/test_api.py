import json

import pytest

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

SAMPLE_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "name": "test-app",
    "packages": [
        {"name": "requests", "versionInfo": "2.31.0", "licenseDeclared": "Apache-2.0"},
    ],
}


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "argus-sbomguard"


# ── Projects ──


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
    assert data["description"] == "A test project"


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


@pytest.mark.asyncio
async def test_project_history_empty(client):
    resp = await client.post("/api/v1/projects", json={"name": "history-test"})
    pid = resp.json()["id"]

    resp = await client.get(f"/api/v1/projects/{pid}/history")
    assert resp.status_code == 200
    assert resp.json()["sboms"] == []


@pytest.mark.asyncio
async def test_project_history_with_sboms(client):
    proj = await client.post("/api/v1/projects", json={"name": "history-sboms"})
    pid = proj.json()["id"]

    await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "version": "v1"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )

    resp = await client.get(f"/api/v1/projects/{pid}/history")
    assert resp.status_code == 200
    assert len(resp.json()["sboms"]) == 1


# ── SBOMs ──


@pytest.mark.asyncio
async def test_upload_sbom_cyclonedx(client):
    proj = await client.post("/api/v1/projects", json={"name": "sbom-cyclonedx"})
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
    assert "sha256" in data


@pytest.mark.asyncio
async def test_upload_sbom_spdx(client):
    proj = await client.post("/api/v1/projects", json={"name": "sbom-spdx"})
    pid = proj.json()["id"]

    resp = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid},
        files={"file": ("spdx.json", json.dumps(SAMPLE_SPDX), "application/json")},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["format"] == "spdx"
    assert data["dependency_count"] == 1


@pytest.mark.asyncio
async def test_upload_sbom_duplicate(client):
    proj = await client.post("/api/v1/projects", json={"name": "sbom-dup"})
    pid = proj.json()["id"]

    resp1 = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    resp2 = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    assert resp1.status_code == 201
    assert resp2.status_code == 201
    assert resp1.json()["id"] == resp2.json()["id"]
    assert resp1.json()["sha256"] == resp2.json()["sha256"]


@pytest.mark.asyncio
async def test_upload_sbom_project_not_found(client):
    resp = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": "00000000-0000-0000-0000-000000000000"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_upload_sbom_invalid_json(client):
    proj = await client.post("/api/v1/projects", json={"name": "sbom-invalid"})
    pid = proj.json()["id"]

    resp = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid},
        files={"file": ("sbom.json", b"not-json", "application/json")},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_sbom_detail(client):
    proj = await client.post("/api/v1/projects", json={"name": "sbom-detail"})
    pid = proj.json()["id"]

    upload = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    sid = upload.json()["id"]

    resp = await client.get(f"/api/v1/sboms/{sid}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == sid
    assert data["dependency_count"] == 2
    assert len(data["dependencies"]) == 2
    assert data["dependencies"][0]["name"] == "lodash"


@pytest.mark.asyncio
async def test_get_sbom_not_found(client):
    resp = await client.get("/api/v1/sboms/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_sbom_diff_added_removed(client):
    proj = await client.post("/api/v1/projects", json={"name": "sbom-diff"})
    pid = proj.json()["id"]

    sbom_a = {"bomFormat": "CycloneDX", "components": [{"name": "a", "version": "1.0"}]}
    sbom_b = {
        "bomFormat": "CycloneDX",
        "components": [
            {"name": "a", "version": "2.0"},
            {"name": "b", "version": "1.0"},
        ],
    }

    r1 = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid},
        files={"file": ("a.json", json.dumps(sbom_a), "application/json")},
    )
    r2 = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid},
        files={"file": ("b.json", json.dumps(sbom_b), "application/json")},
    )

    resp = await client.get(f"/api/v1/sboms/{r1.json()['id']}/diff/{r2.json()['id']}")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["added"]) == 2
    added_names = {d["name"] for d in data["added"]}
    assert added_names == {"a", "b"}
    assert len(data["changed"]) == 1
    assert data["changed"][0]["name"] == "a"
    assert data["changed"][0]["from_version"] == "1.0"
    assert data["changed"][0]["to_version"] == "2.0"


# ── Vulnerabilities ──


@pytest.mark.asyncio
async def test_active_vulnerabilities(client):
    resp = await client.get("/api/v1/vulnerabilities/active")
    assert resp.status_code == 200
    data = resp.json()
    assert "vulnerabilities" in data
    assert "total" in data


@pytest.mark.asyncio
async def test_vulnerability_summary(client):
    resp = await client.get("/api/v1/vulnerabilities/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert "counts" in data
    assert "total" in data
    assert "affected_projects" in data


# ── Alerts ──


@pytest.mark.asyncio
async def test_create_alert(client):
    proj = await client.post("/api/v1/projects", json={"name": "alert-test"})
    pid = proj.json()["id"]

    resp = await client.post(
        "/api/v1/alerts",
        json={
            "project_id": pid,
            "severity_threshold": "critical",
            "notification_type": "email",
            "config": {"to": "admin@example.com"},
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["severity_threshold"] == "critical"
    assert data["notification_type"] == "email"
    assert data["enabled"] is True


@pytest.mark.asyncio
async def test_create_alert_project_not_found(client):
    resp = await client.post(
        "/api/v1/alerts",
        json={
            "project_id": "00000000-0000-0000-0000-000000000000",
            "severity_threshold": "high",
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_alerts(client):
    proj = await client.post("/api/v1/projects", json={"name": "alerts-list"})
    pid = proj.json()["id"]

    await client.post(
        "/api/v1/alerts",
        json={"project_id": pid, "notification_type": "slack"},
    )

    resp = await client.get("/api/v1/alerts")
    assert resp.status_code == 200
    assert len(resp.json()["alerts"]) >= 1


@pytest.mark.asyncio
async def test_delete_alert(client):
    proj = await client.post("/api/v1/projects", json={"name": "alerts-del"})
    pid = proj.json()["id"]

    create = await client.post(
        "/api/v1/alerts",
        json={"project_id": pid, "notification_type": "slack"},
    )
    aid = create.json()["id"]

    resp = await client.delete(f"/api/v1/alerts/{aid}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "deleted"


@pytest.mark.asyncio
async def test_delete_alert_not_found(client):
    resp = await client.delete("/api/v1/alerts/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


# ── Dashboard (HTMX pages) ──


@pytest.mark.asyncio
async def test_dashboard_page(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_projects_page(client):
    resp = await client.get("/projects")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_vulnerabilities_page(client):
    resp = await client.get("/vulnerabilities")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_settings_page(client):
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
