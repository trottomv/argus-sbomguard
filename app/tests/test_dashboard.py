import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from starlette.requests import Request

from api.dashboard import _dep_name, create_api_key_web
from models.auth import ApiKey
from models.sbom import Dependency
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)


def _sbom(name: str, version: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "components": [{"type": "library", "name": name, "version": version}],
    }


class TestDepName:
    def test_with_name_and_version(self):
        assert _dep_name("lodash", "4.17.20", "pkg:npm/lodash@4.17.20") == "lodash 4.17.20"

    def test_with_name_no_version(self):
        assert _dep_name("lodash", None, None) == "lodash"

    def test_purl_with_version(self):
        assert _dep_name(None, None, "pkg:npm/lodash@4.17.20") == "lodash 4.17.20"

    def test_purl_without_version(self):
        assert _dep_name(None, None, "pkg:npm/lodash") == "lodash"

    def test_purl_single_segment(self):
        assert _dep_name(None, None, "lodash") == "lodash"

    def test_purl_query_string(self):
        assert _dep_name(None, None, "pkg:npm/lodash?x=y") == "lodash"

    def test_empty_all(self):
        assert _dep_name(None, None, None) == "-"


async def _upload(
    client, pid: str, name: str, version: str, service_name: str | None = None
) -> str:
    data = {"project_id": pid, "version": version}
    if service_name:
        data["service_name"] = service_name
    resp = await client.post(
        "/api/v1/sboms/upload",
        data=data,
        files={"file": ("sbom.json", json.dumps(_sbom(name, version)), "application/json")},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _service_id(client, pid: str) -> str:
    resp = await client.get(f"/api/v1/services?project_id={pid}")
    return resp.json()[0]["id"]


async def _add_vuln(
    db_session,
    sbom_id: str,
    cve_id: str,
    *,
    severity: VulnerabilitySeverity = VulnerabilitySeverity.HIGH,
    purl: str = "pkg:npm/lodash@4.17.20",
    dep_name: str | None = "lodash",
    dep_version: str | None = "4.17.20",
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN,
) -> None:
    vuln = Vulnerability(
        cve_id=cve_id,
        source="grype",
        severity=severity,
        cvss_score=8.1,
        summary=cve_id,
    )
    db_session.add(vuln)
    await db_session.flush()
    if dep_name:
        db_session.add(
            Dependency(sbom_id=uuid.UUID(sbom_id), name=dep_name, version=dep_version, purl=purl)
        )
    db_session.add(
        SBOMVulnerability(
            sbom_id=uuid.UUID(sbom_id),
            dependency_purl=purl,
            vulnerability_id=vuln.id,
            status=status,
            fixed_at=datetime.now(UTC) if status == VulnerabilityStatus.FIXED else None,
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()


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


# ── Projects list pagination / HTMX ──


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
async def test_dashboard_home(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_refresh_snapshots(client):
    resp = await client.post("/refresh-snapshots")
    assert resp.status_code == 202


# ── Project detail ──


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


# ── Global vulnerabilities page ──


@pytest.mark.asyncio
async def test_vulnerabilities_page_filters(client, db_session):
    proj = await client.post("/api/v1/projects", json={"name": "vulns-page"})
    pid = proj.json()["id"]
    sbom_id = await _upload(client, pid, "a", "1.0", service_name="svc")
    await _add_vuln(db_session, sbom_id, "CVE-2026-3006")
    svc_id = await _service_id(client, pid)

    resp = await client.get("/vulnerabilities?severity=high")
    assert resp.status_code == 200

    resp = await client.get(f"/vulnerabilities?project_id={pid}")
    assert resp.status_code == 200

    resp = await client.get(f"/vulnerabilities?service_id={svc_id}")
    assert resp.status_code == 200

    resp = await client.get("/vulnerabilities?sort=severity&order=asc")
    assert resp.status_code == 200

    resp = await client.get("/vulnerabilities?sort=severity&order=desc")
    assert resp.status_code == 200

    resp = await client.get("/vulnerabilities?sort=cvss_score&order=asc")
    assert resp.status_code == 200

    resp = await client.get("/vulnerabilities?page=2&per_page=1")
    assert resp.status_code == 200

    resp = await client.get("/vulnerabilities", headers={"HX-Request": "true"})
    assert resp.status_code == 200


# ── Settings API keys ──


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


# ── SBOMs page ──


@pytest.mark.asyncio
async def test_sboms_page_filters(client, db_session):
    proj = await client.post("/api/v1/projects", json={"name": "sboms-page"})
    pid = proj.json()["id"]
    sbom_id = await _upload(client, pid, "a", "1.0", service_name="svc")
    await _add_vuln(db_session, sbom_id, "CVE-2026-3007")
    svc_id = await _service_id(client, pid)

    resp = await client.get(f"/sboms?project_id={pid}")
    assert resp.status_code == 200

    resp = await client.get(f"/sboms?service_id={svc_id}")
    assert resp.status_code == 200

    resp = await client.get("/sboms?order=asc")
    assert resp.status_code == 200

    resp = await client.get("/sboms?page=2&per_page=1")
    assert resp.status_code == 200

    resp = await client.get("/sboms", headers={"HX-Request": "true"})
    assert resp.status_code == 200
