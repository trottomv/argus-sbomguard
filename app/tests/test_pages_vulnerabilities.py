from datetime import UTC, datetime

import pytest

from models.project import Project
from models.sbom import SBOM, Dependency, SBOMFormat
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from tests.helpers import _add_vuln, _service_id, _upload


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
