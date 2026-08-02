import json
from unittest.mock import patch

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
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "per_page" in data
    assert "total_pages" in data
    assert len(data["items"]) >= 2


@pytest.mark.asyncio
async def test_list_projects_pagination(client):
    await client.post("/api/v1/projects", json={"name": "p1"})
    await client.post("/api/v1/projects", json={"name": "p2"})
    await client.post("/api/v1/projects", json={"name": "p3"})

    resp = await client.get("/api/v1/projects?page=1&per_page=2")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["total"] >= 3
    assert data["total_pages"] >= 2
    assert data["page"] == 1
    assert data["per_page"] == 2

    resp2 = await client.get("/api/v1/projects?page=2&per_page=2")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["items"]) >= 1
    assert data2["page"] == 2


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
async def test_delete_project(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "to-delete"})
    pid = create_resp.json()["id"]

    delete_resp = await client.delete(f"/api/v1/projects/{pid}")
    assert delete_resp.status_code == 204

    get_resp = await client.get(f"/api/v1/projects/{pid}")
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_project_cascades_snapshots(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "cascade-test"})
    pid = create_resp.json()["id"]

    await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "version": "v1"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )

    delete_resp = await client.delete(f"/api/v1/projects/{pid}")
    assert delete_resp.status_code == 204

    get_resp = await client.get(f"/api/v1/projects/{pid}")
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_project_history_empty(client):
    resp = await client.post("/api/v1/projects", json={"name": "history-test"})
    pid = resp.json()["id"]

    resp = await client.get(f"/api/v1/projects/{pid}/history")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert data["items"] == []
    assert data["total"] == 0
    assert "page" in data


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
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["total"] == 1


@pytest.mark.asyncio
async def test_project_history_pagination(client):
    proj = await client.post("/api/v1/projects", json={"name": "hist-pag"})
    pid = proj.json()["id"]

    base = {
        "bomFormat": "CycloneDX",
        "components": [{"name": "lodash", "version": "4.17.20"}],
    }

    for v in ["v1", "v2", "v3"]:
        content = dict(base)
        content["version"] = v  # different version field in SBOM -> different SHA256
        await client.post(
            "/api/v1/sboms/upload",
            data={"project_id": pid, "version": v},
            files={"file": ("sbom.json", json.dumps(content), "application/json")},
        )

    resp = await client.get(f"/api/v1/projects/{pid}/history?page=1&per_page=2")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["total"] >= 3
    assert data["total_pages"] >= 2


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
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "per_page" in data
    assert "total_pages" in data


@pytest.mark.asyncio
async def test_active_vulnerabilities_pagination(client):
    resp = await client.get("/api/v1/vulnerabilities/active?page=1&per_page=10")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) <= 10
    assert data["page"] == 1
    assert data["per_page"] == 10


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
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert len(data["items"]) >= 1


@pytest.mark.asyncio
async def test_list_alerts_pagination(client):
    resp = await client.get("/api/v1/alerts?page=1&per_page=5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["page"] == 1
    assert data["per_page"] == 5


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
async def test_refresh_snapshots(client):
    with patch("api.dashboard.snapshot_metrics") as mock_task:
        resp = await client.post("/refresh-snapshots")
    assert resp.status_code == 202
    mock_task.delay.assert_called_once_with()


@pytest.mark.asyncio
async def test_projects_page(client):
    resp = await client.get("/projects")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_projects_page_pagination(client):
    resp = await client.get("/projects?page=1&per_page=10")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_vulnerabilities_page(client):
    resp = await client.get("/vulnerabilities")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_vulnerabilities_page_pagination(client):
    resp = await client.get("/vulnerabilities?page=1&per_page=10&sort=cvss_score&order=desc")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_settings_page(client):
    resp = await client.get("/settings")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_sboms_page(client):
    resp = await client.get("/sboms")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_sboms_page_pagination(client):
    resp = await client.get("/sboms?page=1&per_page=10&sort=created_at&order=desc")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_project_detail_page(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "detail-html"})
    pid = create_resp.json()["id"]

    resp = await client.get(f"/projects/{pid}")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_project_sboms_lazy_load(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "lazy-test"})
    pid = create_resp.json()["id"]

    await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "version": "v1"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )

    resp = await client.get(f"/projects/{pid}/sboms?page=1&per_page=25")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


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
