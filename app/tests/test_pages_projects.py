import json
import uuid
from datetime import UTC, datetime

import pytest

from api.pages.projects import _get_project_vulns
from models.project import Project
from models.sbom import SBOM, SBOMFormat
from models.service import Service
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


@pytest.mark.asyncio
async def test_projects_page_search_filter(client):
    await client.post("/api/v1/projects", json={"name": "Payment Service"})
    await client.post("/api/v1/projects", json={"name": "Billing API"})

    resp = await client.get("/projects?q=payment")
    assert resp.status_code == 200
    assert "Payment Service" in resp.text
    assert "Billing API" not in resp.text
    assert 'value="payment"' in resp.text
    assert "Clear search" in resp.text


@pytest.mark.asyncio
async def test_projects_page_without_search_hides_clear_button(client):
    resp = await client.get("/projects")
    assert resp.status_code == 200
    assert "Clear search" not in resp.text


@pytest.mark.asyncio
async def test_projects_page_search_no_match(client):
    await client.post("/api/v1/projects", json={"name": "Payment Service"})

    resp = await client.get("/projects?q=nomatch")
    assert resp.status_code == 200
    assert 'No projects match "nomatch"' in resp.text


@pytest.mark.asyncio
async def test_projects_page_search_treats_wildcards_literally(client):
    await client.post("/api/v1/projects", json={"name": "Payment Service"})

    resp = await client.get("/projects?q=%25")
    assert resp.status_code == 200
    assert "Payment Service" not in resp.text


@pytest.mark.asyncio
async def test_projects_page_search_propagates_to_load_more(client):
    for idx in range(3):
        await client.post("/api/v1/projects", json={"name": f"payment-{idx}"})

    resp = await client.get("/projects?q=payment&per_page=1")
    assert resp.status_code == 200
    assert "/projects?page=2&per_page=1&q=payment" in resp.text


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


@pytest.mark.asyncio
async def test_project_sboms_page_offset(client):
    proj = await client.post("/api/v1/projects", json={"name": "offset-test"})
    pid = proj.json()["id"]
    for name in ("a", "b", "c", "d"):
        await _upload(client, pid, name, "1.0")

    resp = await client.get(f"/projects/{pid}/sboms?per_page=2&offset=1")
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


@pytest.mark.asyncio
async def test_project_detail_vuln_accept_scopes(client, db_session):
    proj = await client.post("/api/v1/projects", json={"name": "detail-scopes"})
    pid = proj.json()["id"]
    sbom_id = await _upload(client, pid, "a", "1.0", service_name="svc")
    await _add_vuln(db_session, sbom_id, "CVE-2026-5004")

    resp = await client.get(f"/projects/{pid}")
    assert resp.status_code == 200
    assert "CVE-2026-5004" in resp.text
    # The row embeds the valid accept scopes for the modal.
    assert "project_name" in resp.text


async def _add_open_vuln(db_session, sbom: SBOM, cve_id: str) -> None:
    vuln = Vulnerability(cve_id=cve_id, source="grype", severity=VulnerabilitySeverity.HIGH)
    db_session.add(vuln)
    await db_session.flush()
    db_session.add(
        SBOMVulnerability(
            sbom_id=sbom.id,
            dependency_purl=f"pkg:npm/{cve_id}@1.0.0",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )


@pytest.mark.asyncio
async def test_project_vulns_use_latest_by_created_at(db_session):
    project = Project(name="latest-by-created")
    db_session.add(project)
    await db_session.flush()
    service = Service(project_id=project.id, name="svc")
    db_session.add(service)
    await db_session.flush()

    older = SBOM(
        project_id=project.id,
        service_id=service.id,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="1" * 64,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        uploaded_at=datetime(2026, 1, 2, tzinfo=UTC),
    )
    newer = SBOM(
        project_id=project.id,
        service_id=service.id,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="2" * 64,
        created_at=datetime(2026, 1, 2, tzinfo=UTC),
        uploaded_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    db_session.add_all([older, newer])
    await db_session.flush()
    await _add_open_vuln(db_session, older, "CVE-2026-7001")
    await _add_open_vuln(db_session, newer, "CVE-2026-7002")
    await db_session.commit()

    result = await _get_project_vulns(db_session, project.id, project_name=project.name)

    assert [item["cve_id"] for item in result] == ["CVE-2026-7002"]


@pytest.mark.asyncio
async def test_project_vulns_tie_break_on_newest_id(db_session):
    project = Project(name="latest-tie")
    db_session.add(project)
    await db_session.flush()
    service = Service(project_id=project.id, name="svc")
    db_session.add(service)
    await db_session.flush()

    same_time = datetime(2026, 1, 1, tzinfo=UTC)
    lower = SBOM(
        id=uuid.UUID(int=1),
        project_id=project.id,
        service_id=service.id,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="3" * 64,
        created_at=same_time,
        uploaded_at=same_time,
    )
    higher = SBOM(
        id=uuid.UUID(int=2),
        project_id=project.id,
        service_id=service.id,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="4" * 64,
        created_at=same_time,
        uploaded_at=same_time,
    )
    db_session.add_all([lower, higher])
    await db_session.flush()
    await _add_open_vuln(db_session, lower, "CVE-2026-7003")
    await _add_open_vuln(db_session, higher, "CVE-2026-7004")
    await db_session.commit()

    result = await _get_project_vulns(db_session, project.id, project_name=project.name)

    assert [item["cve_id"] for item in result] == ["CVE-2026-7004"]
