import json
import uuid
from datetime import UTC, datetime

import pytest

from models.project import Project
from models.sbom import SBOM, SBOMFormat
from models.service import Service
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


@pytest.mark.asyncio
async def test_active_vulnerabilities_services_exclude_fixed(client, db_session):
    project = Project(name="vuln-svc-fixed")
    db_session.add(project)
    await db_session.flush()

    svc_a = Service(project_id=project.id, name="svc-a")
    svc_b = Service(project_id=project.id, name="svc-b")
    db_session.add_all([svc_a, svc_b])
    await db_session.flush()

    sbom_a = SBOM(
        project_id=project.id,
        service_id=svc_a.id,
        version="v1",
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="d" * 64,
    )
    sbom_b = SBOM(
        project_id=project.id,
        service_id=svc_b.id,
        version="v1",
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="e" * 64,
    )
    db_session.add_all([sbom_a, sbom_b])
    await db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2026-4003",
        source="grype",
        severity=VulnerabilitySeverity.CRITICAL,
        cvss_score=9.8,
        summary="svc label test",
    )
    db_session.add(vuln)
    await db_session.flush()

    db_session.add_all(
        [
            SBOMVulnerability(
                sbom_id=sbom_a.id,
                dependency_purl="pkg:npm/lodash@4.17.20",
                vulnerability_id=vuln.id,
                status=VulnerabilityStatus.OPEN,
                detected_at=datetime.now(UTC),
            ),
            SBOMVulnerability(
                sbom_id=sbom_b.id,
                dependency_purl="pkg:npm/lodash@4.17.20",
                vulnerability_id=vuln.id,
                status=VulnerabilityStatus.FIXED,
                fixed_at=datetime.now(UTC),
                detected_at=datetime.now(UTC),
            ),
        ]
    )
    await db_session.commit()

    resp = await client.get("/api/v1/vulnerabilities/active")
    assert resp.status_code == 200
    items = [item for item in resp.json()["items"] if item["cve_id"] == "CVE-2026-4003"]
    assert len(items) == 1
    assert items[0]["services"] == ["svc-a"]
    assert items[0]["projects"] == ["vuln-svc-fixed"]
