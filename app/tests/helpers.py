import json
import uuid
from datetime import UTC, datetime

from models.sbom import Dependency
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


def _sbom(name: str, version: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "components": [{"type": "library", "name": name, "version": version}],
    }


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
