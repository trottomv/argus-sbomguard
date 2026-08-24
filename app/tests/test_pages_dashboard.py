import re
from datetime import UTC, datetime
from unittest.mock import patch

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


@pytest.mark.asyncio
async def test_dashboard_page(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_dashboard_home(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_dashboard_critical_count_is_open_anywhere(client, db_session):
    project = Project(name="dash-count")
    db_session.add(project)
    await db_session.flush()

    svc_a = Service(project_id=project.id, name="svc-a")
    svc_b = Service(project_id=project.id, name="svc-b")
    db_session.add_all([svc_a, svc_b])
    await db_session.flush()

    sbom_a = SBOM(
        project_id=project.id,
        service_id=svc_a.id,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="a" * 64,
    )
    sbom_b = SBOM(
        project_id=project.id,
        service_id=svc_b.id,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="b" * 64,
    )
    db_session.add_all([sbom_a, sbom_b])
    await db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2026-5001",
        source="grype",
        severity=VulnerabilitySeverity.CRITICAL,
        cvss_score=9.8,
        summary="dash count test",
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

    resp = await client.get("/")
    assert resp.status_code == 200
    match = re.search(
        r'<a href="/vulnerabilities\?severity=critical".*?text-ctp-red mt-1">(\d+)</p>',
        resp.text,
        re.DOTALL,
    )
    assert match is not None
    assert match.group(1) == "1"


@pytest.mark.asyncio
async def test_refresh_snapshots(client):
    resp = await client.post("/refresh-snapshots")
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_refresh_snapshots_dispatches_task(client):
    with patch("api.pages.dashboard.snapshot_metrics") as mock_task:
        resp = await client.post("/refresh-snapshots")
    assert resp.status_code == 202
    mock_task.delay.assert_called_once_with()
