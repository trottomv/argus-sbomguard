import json
import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

import main
from models.project import Project
from models.sbom import SBOM, Dependency, SBOMFormat
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)

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
async def test_healthz(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "argus-sbomguard"


@pytest.mark.asyncio
async def test_readyz_ok(client):
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["checks"] == {"database": "ok", "rabbitmq": "ok"}


@pytest.mark.asyncio
async def test_readyz_database_failure(client, monkeypatch):
    class FailingConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, *args, **kwargs):
            raise Exception("db down")

    class FailingEngine:
        def connect(self):
            return FailingConn()

    monkeypatch.setattr(main, "engine", FailingEngine())
    resp = await client.get("/readyz")
    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "error"
    assert data["checks"]["database"] == "error"
    assert data["checks"]["rabbitmq"] == "ok"


@pytest.mark.asyncio
async def test_readyz_rabbitmq_failure(client, monkeypatch):
    class OkConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, *args, **kwargs):
            return None

    class OkEngine:
        def connect(self):
            return OkConn()

    monkeypatch.setattr(main, "engine", OkEngine())

    def boom_connection(*args, **kwargs):
        raise OSError("rabbitmq down")

    monkeypatch.setattr(main.asyncio, "open_connection", boom_connection)
    resp = await client.get("/readyz")
    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "error"
    assert data["checks"]["database"] == "ok"
    assert data["checks"]["rabbitmq"] == "error"


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
async def test_create_project_slug_generated(client):
    resp = await client.post("/api/v1/projects", json={"name": "My New Service"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["slug"] == "my-new-service"
    assert data["id"] != data["slug"]


@pytest.mark.asyncio
async def test_create_project_slug_collision_409(client):
    await client.post("/api/v1/projects", json={"name": "Foo Bar"})
    resp = await client.post("/api/v1/projects", json={"name": "foo_bar"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_project_slug_in_list_and_get(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "slug-lookup"})
    pid = create_resp.json()["id"]
    assert create_resp.json()["slug"] == "slug-lookup"

    get_resp = await client.get(f"/api/v1/projects/{pid}")
    assert get_resp.status_code == 200
    assert get_resp.json()["slug"] == "slug-lookup"

    list_resp = await client.get("/api/v1/projects")
    items = list_resp.json()["items"]
    assert any(item["slug"] == "slug-lookup" for item in items)


@pytest.mark.asyncio
async def test_create_project_non_ascii_name(client):
    resp = await client.post("/api/v1/projects", json={"name": "Mio Progetto"})
    assert resp.status_code == 201
    assert resp.json()["slug"] == "mio-progetto"


@pytest.mark.asyncio
async def test_create_project_requires_alphanumeric(client):
    resp = await client.post("/api/v1/projects", json={"name": "!!!"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_rename_project_requires_alphanumeric(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "renamable"})
    pid = create_resp.json()["id"]

    resp = await client.patch(f"/api/v1/projects/{pid}", json={"name": "###"})
    assert resp.status_code == 422


def test_is_slug_conflict_helper():
    from sqlalchemy.exc import IntegrityError

    from api.projects import _is_slug_conflict

    class SlugOrig:
        constraint_name = "ix_projects_slug"

    class NameOrig:
        constraint_name = "ix_projects_name"

    assert _is_slug_conflict(IntegrityError("stmt", {}, SlugOrig()))
    assert not _is_slug_conflict(IntegrityError("stmt", {}, NameOrig()))


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

    for version in ["v1", "v2", "v3"]:
        content = dict(base)
        content["version"] = version  # different version field in SBOM -> different SHA256
        await client.post(
            "/api/v1/sboms/upload",
            data={"project_id": pid, "version": version},
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
async def test_upload_sbom_by_slug(client):
    proj = await client.post("/api/v1/projects", json={"name": "slug-upload"})
    slug = proj.json()["slug"]

    resp = await client.post(
        "/api/v1/sboms/upload",
        data={"slug": slug, "version": "v1.0.0"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    assert resp.status_code == 201
    assert resp.json()["format"] == "cyclonedx"


@pytest.mark.asyncio
async def test_upload_sbom_slug_not_found(client):
    resp = await client.post(
        "/api/v1/sboms/upload",
        data={"slug": "does-not-exist"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_upload_sbom_invalid_project_id_uuid(client):
    resp = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": "not-a-uuid"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_upload_sbom_requires_identifier(client):
    resp = await client.post(
        "/api/v1/sboms/upload",
        data={},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_upload_sbom_id_and_slug_conflict(client):
    proj = await client.post("/api/v1/projects", json={"name": "both-ids"})
    pid = proj.json()["id"]
    slug = proj.json()["slug"]
    resp = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "slug": slug},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    assert resp.status_code == 422


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
    added_names = {dep["name"] for dep in data["added"]}
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
async def test_vulnerabilities_page_shows_library_and_fixed_version(client, db_session):
    project = Project(name="lib-fix-test")
    db_session.add(project)
    await db_session.flush()

    sbom = SBOM(
        project_id=project.id,
        version="v1",
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="a" * 64,
    )
    db_session.add(sbom)
    await db_session.flush()

    db_session.add_all(
        [
            Dependency(
                sbom_id=sbom.id, name="lodash", version="4.17.20", purl="pkg:npm/lodash@4.17.20"
            ),
            Dependency(
                sbom_id=sbom.id, name="react", version="18.2.0", purl="pkg:npm/react@18.2.0"
            ),
            Dependency(sbom_id=sbom.id, name="axios", version="1.7.0", purl="pkg:npm/axios@1.7.0"),
        ]
    )
    await db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2026-0001",
        source="grype",
        severity=VulnerabilitySeverity.HIGH,
        cvss_score=8.1,
        summary="Lodash RCE",
        affected_packages=["pkg:npm/lodash@4.17.20"],
        extra_data={"fix": {"versions": ["4.17.21"], "state": "fixed"}},
    )
    db_session.add(vuln)
    await db_session.flush()

    db_session.add_all(
        [
            SBOMVulnerability(
                sbom_id=sbom.id,
                dependency_purl="pkg:npm/lodash@4.17.20",
                vulnerability_id=vuln.id,
                status=VulnerabilityStatus.OPEN,
                detected_at=datetime.now(UTC),
            ),
            SBOMVulnerability(
                sbom_id=sbom.id,
                dependency_purl="pkg:npm/react@18.2.0",
                vulnerability_id=vuln.id,
                status=VulnerabilityStatus.OPEN,
                detected_at=datetime.now(UTC),
            ),
            SBOMVulnerability(
                sbom_id=sbom.id,
                dependency_purl="pkg:npm/axios@1.7.0",
                vulnerability_id=vuln.id,
                status=VulnerabilityStatus.FIXED,
                detected_at=datetime.now(UTC),
            ),
        ]
    )
    await db_session.commit()

    resp = await client.get("/vulnerabilities")
    assert resp.status_code == 200
    html = resp.text
    assert "CVE-2026-0001" in html
    assert "lodash 4.17.20" in html
    assert "react 18.2.0" in html
    assert "4.17.21" in html
    assert "axios 1.7.0" not in html
    assert html.index("lodash 4.17.20") < html.index("react 18.2.0")


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


@pytest.mark.asyncio
async def test_ui_rename_project_slug_collision_409(client):
    await client.post("/api/v1/projects", json={"name": "Payment Service"})
    create_resp = await client.post("/api/v1/projects", json={"name": "Other"})
    pid = create_resp.json()["id"]

    resp = await client.patch(f"/projects/{pid}/name", data={"name": "Payment-Service"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_ui_rename_project_requires_alphanumeric(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "renamable-ui"})
    pid = create_resp.json()["id"]

    resp = await client.patch(f"/projects/{pid}/name", data={"name": "###"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ui_rename_project_ok(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "rename-me"})
    pid = create_resp.json()["id"]

    resp = await client.patch(f"/projects/{pid}/name", data={"name": "Renamed"})
    assert resp.status_code == 200
    assert "Renamed" in resp.text


# ── Projects — update/delete edge cases ──


@pytest.mark.asyncio
async def test_delete_project_not_found(client):
    resp = await client.delete("/api/v1/projects/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_project(client):
    create = await client.post("/api/v1/projects", json={"name": "update-me"})
    pid = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/projects/{pid}",
        json={
            "name": "updated",
            "description": "desc",
            "repo_url": "https://example.com",
            "platform": "github",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "updated"
    assert data["slug"] == "updated"
    assert data["description"] == "desc"
    assert data["repo_url"] == "https://example.com"
    assert data["platform"] == "github"


@pytest.mark.asyncio
async def test_update_project_not_found(client):
    resp = await client.patch(
        "/api/v1/projects/00000000-0000-0000-0000-000000000000",
        json={"name": "x"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_project_name_conflict(client):
    await client.post("/api/v1/projects", json={"name": "taken"})
    create = await client.post("/api/v1/projects", json={"name": "other"})
    pid = create.json()["id"]

    resp = await client.patch(f"/api/v1/projects/{pid}", json={"name": "taken"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_update_project_slug_collision_409(client):
    await client.post("/api/v1/projects", json={"name": "foo_bar"})
    create = await client.post("/api/v1/projects", json={"name": "a"})
    pid = create.json()["id"]

    resp = await client.patch(f"/api/v1/projects/{pid}", json={"name": "Foo Bar"})
    assert resp.status_code == 409


# ── Alerts — update ──


@pytest.mark.asyncio
async def test_update_alert(client):
    proj = await client.post("/api/v1/projects", json={"name": "alert-update"})
    pid = proj.json()["id"]
    create = await client.post(
        "/api/v1/alerts",
        json={
            "project_id": pid,
            "severity_threshold": "high",
            "notification_type": "email",
            "enabled": True,
        },
    )
    aid = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/alerts/{aid}",
        json={
            "project_id": pid,
            "severity_threshold": "critical",
            "notification_type": "slack",
            "enabled": False,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "updated"


@pytest.mark.asyncio
async def test_update_alert_project_not_found(client):
    proj = await client.post("/api/v1/projects", json={"name": "alert-upd-pnf"})
    pid = proj.json()["id"]
    create = await client.post("/api/v1/alerts", json={"project_id": pid})
    aid = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/alerts/{aid}",
        json={"project_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_alert_not_found(client):
    resp = await client.patch(
        "/api/v1/alerts/00000000-0000-0000-0000-000000000000",
        json={"enabled": False},
    )
    assert resp.status_code == 404


# ── API keys ──


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


# ── SBOMs — download, delete ──


@pytest.mark.asyncio
async def test_download_sbom(client):
    proj = await client.post("/api/v1/projects", json={"name": "sbom-download"})
    pid = proj.json()["id"]
    upload = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    sid = upload.json()["id"]

    resp = await client.get(f"/api/v1/sboms/{sid}/download")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json()["bomFormat"] == "CycloneDX"


@pytest.mark.asyncio
async def test_download_sbom_not_found(client):
    resp = await client.get("/api/v1/sboms/00000000-0000-0000-0000-000000000000/download")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_sbom_not_found(client):
    resp = await client.delete("/api/v1/sboms/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_sbom_reconciles_older_fixed_vulns(client, db_session):
    proj = await client.post("/api/v1/projects", json={"name": "sbom-delete-recon"})
    pid = proj.json()["id"]

    sbom_a = {"bomFormat": "CycloneDX", "components": [{"name": "keep", "version": "1.0"}]}
    sbom_b = {"bomFormat": "CycloneDX", "components": [{"name": "newer", "version": "2.0"}]}
    r1 = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "service_name": "svc"},
        files={"file": ("a.json", json.dumps(sbom_a), "application/json")},
    )
    r2 = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "service_name": "svc"},
        files={"file": ("b.json", json.dumps(sbom_b), "application/json")},
    )
    older_sid = r1.json()["id"]
    newest_sid = r2.json()["id"]

    vuln = Vulnerability(
        cve_id="CVE-2026-0199", source="grype", severity=VulnerabilitySeverity.HIGH
    )
    db_session.add(vuln)
    await db_session.flush()
    db_session.add(
        SBOMVulnerability(
            sbom_id=uuid.UUID(older_sid),
            dependency_purl="pkg:npm/keep@1.0.0",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.FIXED,
            fixed_at=datetime.now(UTC),
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    resp = await client.delete(f"/api/v1/sboms/{newest_sid}")
    assert resp.status_code == 204


# ── Vulnerabilities — active filters and sorting ──


@pytest.mark.asyncio
async def test_active_vulnerabilities_filters_and_sort(client, db_session):
    proj = await client.post("/api/v1/projects", json={"name": "vuln-active"})
    pid = proj.json()["id"]
    upload = await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "service_name": "svc"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )
    sid = upload.json()["id"]

    vuln = Vulnerability(
        cve_id="CVE-2026-0102",
        source="grype",
        severity=VulnerabilitySeverity.HIGH,
        cvss_score=8.1,
        summary="Active filter test",
        published_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    db_session.add(vuln)
    await db_session.flush()
    db_session.add(
        SBOMVulnerability(
            sbom_id=uuid.UUID(sid),
            dependency_purl="pkg:npm/lodash@4.17.20",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    resp = await client.get("/api/v1/vulnerabilities/active?severity=high")
    assert resp.status_code == 200
    assert len(resp.json()["items"]) == 1

    resp = await client.get(f"/api/v1/vulnerabilities/active?project_id={pid}")
    assert resp.status_code == 200
    assert resp.json()["items"][0]["cve_id"] == "CVE-2026-0102"

    svcs = await client.get(f"/api/v1/services?project_id={pid}")
    svc_id = svcs.json()[0]["id"]
    resp = await client.get(f"/api/v1/vulnerabilities/active?service_id={svc_id}")
    assert resp.status_code == 200
    assert resp.json()["items"][0]["cve_id"] == "CVE-2026-0102"

    resp = await client.get("/api/v1/vulnerabilities/active?sort=severity&order=desc")
    assert resp.status_code == 200
    assert resp.json()["items"][0]["cve_id"] == "CVE-2026-0102"

    resp = await client.get("/api/v1/vulnerabilities/active?sort=severity&order=asc")
    assert resp.status_code == 200
    assert resp.json()["items"][0]["cve_id"] == "CVE-2026-0102"

    resp = await client.get("/api/v1/vulnerabilities/active?sort=published_at&order=asc")
    assert resp.status_code == 200
    assert resp.json()["items"][0]["cve_id"] == "CVE-2026-0102"

    resp = await client.get("/api/v1/vulnerabilities/active?sort=published_at&order=desc")
    assert resp.status_code == 200
    assert resp.json()["items"][0]["cve_id"] == "CVE-2026-0102"
    assert resp.json()["items"][0]["projects"] == ["vuln-active"]
    assert resp.json()["items"][0]["services"] == ["svc"]
