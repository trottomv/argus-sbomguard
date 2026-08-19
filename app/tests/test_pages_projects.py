import json
import uuid
from datetime import UTC, datetime

import pytest

from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from tests.helpers import SAMPLE_CYCLONEDX, _add_vuln, _service_id, _upload

# ── Project name editing ──


@pytest.mark.asyncio
async def test_edit_project_name(client):
    proj = await client.post("/api/v1/projects", json={"name": "edit-name"})
    pid = proj.json()["id"]

    resp = await client.get(f"/projects/{pid}/edit-name")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_edit_project_name_not_found(client):
    resp = await client.get("/projects/00000000-0000-0000-0000-000000000000/edit-name")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cancel_edit_project_name(client):
    proj = await client.post("/api/v1/projects", json={"name": "cancel-edit"})
    pid = proj.json()["id"]

    resp = await client.get(f"/projects/{pid}/cancel-edit-name")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_cancel_edit_project_name_not_found(client):
    resp = await client.get("/projects/00000000-0000-0000-0000-000000000000/cancel-edit-name")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_project_name_not_found(client):
    resp = await client.patch(
        "/projects/00000000-0000-0000-0000-000000000000/name", data={"name": "x"}
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_project_name_conflict(client):
    await client.post("/api/v1/projects", json={"name": "taken"})
    proj = await client.post("/api/v1/projects", json={"name": "other"})
    pid = proj.json()["id"]

    resp = await client.patch(f"/projects/{pid}/name", data={"name": "taken"})
    assert resp.status_code == 409


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


# ── Projects list pagination / HTMX ──


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
async def test_projects_page_second_page(client):
    for idx in range(3):
        await client.post("/api/v1/projects", json={"name": f"proj-{idx}"})

    resp = await client.get("/projects?page=2&per_page=2")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_projects_page_htmx(client):
    resp = await client.get("/projects", headers={"HX-Request": "true"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_projects_page_first_page(client):
    resp = await client.get("/projects")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


# ── Project detail ──


@pytest.mark.asyncio
async def test_project_detail_page(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "detail-html"})
    pid = create_resp.json()["id"]

    resp = await client.get(f"/projects/{pid}")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_project_detail_not_found(client):
    resp = await client.get("/projects/00000000-0000-0000-0000-000000000000")
    assert resp.status_code in (302, 307)


@pytest.mark.asyncio
async def test_project_detail_with_vulns(client, db_session):
    proj = await client.post("/api/v1/projects", json={"name": "detail-vulns"})
    pid = proj.json()["id"]
    sbom_no_svc = await _upload(client, pid, "a", "1.0")
    sbom_svc = await _upload(client, pid, "b", "1.0", service_name="svc")
    svc_id = await _service_id(client, pid)

    await _add_vuln(db_session, sbom_svc, "CVE-2026-3001")

    dup = Vulnerability(
        cve_id="CVE-2026-3010", source="grype", severity=VulnerabilitySeverity.HIGH, cvss_score=8.0
    )
    db_session.add(dup)
    await db_session.flush()
    for purl in ("pkg:npm/dup@1.0.0", "pkg:npm/dup@2.0.0"):
        db_session.add(
            SBOMVulnerability(
                sbom_id=uuid.UUID(sbom_svc),
                dependency_purl=purl,
                vulnerability_id=dup.id,
                status=VulnerabilityStatus.OPEN,
                detected_at=datetime.now(UTC),
            )
        )
    await db_session.commit()

    await _add_vuln(
        db_session, sbom_svc, "CVE-2026-3002", purl="pkg:npm/react@18.2.0", dep_name=None
    )
    await _add_vuln(db_session, sbom_no_svc, "CVE-2026-3003", purl="pkg:npm/simple", dep_name=None)
    await _add_vuln(db_session, sbom_no_svc, "CVE-2026-3004", purl="simplepkg", dep_name=None)
    await _add_vuln(
        db_session,
        sbom_no_svc,
        "CVE-2026-3005",
        purl="pkg:npm/fixed@1.0.0",
        status=VulnerabilityStatus.FIXED,
    )

    resp = await client.get(f"/projects/{pid}?service_id={svc_id}")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]

    resp = await client.get(f"/projects/{pid}")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


# ── Project SBOM history ──


@pytest.mark.asyncio
async def test_project_sboms_page_not_found(client):
    resp = await client.get("/projects/00000000-0000-0000-0000-000000000000/sboms")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_project_sboms_page_with_vulns(client, db_session):
    proj = await client.post("/api/v1/projects", json={"name": "sboms-vulns"})
    pid = proj.json()["id"]
    sbom_id = await _upload(client, pid, "a", "1.0", service_name="svc")
    await _add_vuln(db_session, sbom_id, "CVE-2026-3003")
    await _add_vuln(
        db_session,
        sbom_id,
        "CVE-2026-3004",
        purl="pkg:npm/react@18.2.0",
        status=VulnerabilityStatus.FIXED,
    )
    svc_id = await _service_id(client, pid)

    resp = await client.get(f"/projects/{pid}/sboms?service_id={svc_id}")
    assert resp.status_code == 200


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


# ── Project vulnerabilities ──


@pytest.mark.asyncio
async def test_project_vulns_page_not_found(client):
    resp = await client.get("/projects/00000000-0000-0000-0000-000000000000/vulns")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_project_vulns_page_no_sboms(client):
    proj = await client.post("/api/v1/projects", json={"name": "proj-vulns-empty"})
    pid = proj.json()["id"]

    resp = await client.get(f"/projects/{pid}/vulns")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_project_vulns_page(client, db_session):
    proj = await client.post("/api/v1/projects", json={"name": "proj-vulns"})
    pid = proj.json()["id"]
    sbom_id = await _upload(client, pid, "a", "1.0", service_name="svc")
    await _add_vuln(db_session, sbom_id, "CVE-2026-3005", purl="pkg:npm/simple")
    svc_id = await _service_id(client, pid)

    resp = await client.get(f"/projects/{pid}/vulns?service_id={svc_id}")
    assert resp.status_code == 200

    resp = await client.get(f"/projects/{pid}/vulns?page=2&per_page=1")
    assert resp.status_code == 200
