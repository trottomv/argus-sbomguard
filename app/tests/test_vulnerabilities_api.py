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
from tests.helpers import SAMPLE_CYCLONEDX


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
