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
from tests.helpers import SAMPLE_CYCLONEDX, SAMPLE_SPDX


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
