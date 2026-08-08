import hashlib
import json
import uuid

import pytest
from sqlalchemy import select

from models.project import Project
from models.sbom import SBOMFormat
from services.sbom_parser import (
    _extract_license,
    _extract_service_name,
    _extract_timestamp,
    compute_sha256,
    parse_cyclonedx,
    parse_spdx,
    store_sbom,
)

CYCLONEDX_SAMPLE = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "components": [
        {
            "type": "library",
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "react",
            "version": "18.2.0",
            "purl": "pkg:npm/react@18.2.0",
        },
    ],
}

SPDX_SAMPLE = {
    "spdxVersion": "SPDX-2.3",
    "name": "test-sbom",
    "packages": [
        {
            "name": "lodash",
            "versionInfo": "4.17.20",
            "licenseDeclared": "MIT",
        },
    ],
}


def test_compute_sha256():
    data = {"foo": "bar"}
    expected = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    assert compute_sha256(data) == expected
    assert compute_sha256({"a": 1}) == compute_sha256({"a": 1})
    assert compute_sha256({"a": 1}) != compute_sha256({"a": 2})


def test_parse_cyclonedx():
    deps = parse_cyclonedx(CYCLONEDX_SAMPLE)
    assert len(deps) == 2
    assert deps[0]["name"] == "lodash"
    assert deps[0]["version"] == "4.17.20"
    assert deps[0]["purl"] == "pkg:npm/lodash@4.17.20"
    assert deps[0]["is_direct"] is True
    assert deps[1]["name"] == "react"


def test_parse_cyclonedx_empty():
    deps = parse_cyclonedx({})
    assert deps == []


def test_parse_cyclonedx_with_license():
    deps = parse_cyclonedx(CYCLONEDX_SAMPLE)
    assert deps[0]["license"] == "MIT"
    assert deps[1]["license"] == ""


def test_extract_license():
    comp = {"licenses": [{"license": {"id": "Apache-2.0"}}]}
    assert _extract_license(comp) == "Apache-2.0"

    comp = {"licenses": []}
    assert _extract_license(comp) == ""

    comp = {}
    assert _extract_license(comp) == ""


def test_parse_spdx():
    deps = parse_spdx(SPDX_SAMPLE)
    assert len(deps) == 1
    assert deps[0]["name"] == "lodash"
    assert deps[0]["version"] == "4.17.20"
    assert deps[0]["license"] == "MIT"
    assert deps[0]["is_direct"] is True


def test_parse_spdx_empty():
    deps = parse_spdx({})
    assert deps == []


@pytest.mark.asyncio
async def test_store_sbom_cyclonedx(db_session):
    project_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    db_session.add(Project(id=project_id, name="SBOM parser 1"))
    await db_session.flush()
    sbom = await store_sbom(db_session, project_id, CYCLONEDX_SAMPLE, version="v1")
    assert sbom.format == SBOMFormat.CYCLONEDX
    assert sbom.dependency_count == 2
    assert sbom.version == "v1"
    assert len(sbom.raw_sbom["components"]) == 2


@pytest.mark.asyncio
async def test_store_sbom_spdx(db_session):
    project_id = uuid.UUID("00000000-0000-0000-0000-000000000002")
    db_session.add(Project(id=project_id, name="SBOM parser 2"))
    await db_session.flush()
    sbom = await store_sbom(db_session, project_id, SPDX_SAMPLE)
    assert sbom.format == SBOMFormat.SPDX
    assert sbom.dependency_count == 1


@pytest.mark.asyncio
async def test_store_sbom_duplicate(db_session):
    project_id = uuid.UUID("00000000-0000-0000-0000-000000000003")
    db_session.add(Project(id=project_id, name="SBOM parser 3"))
    await db_session.flush()
    sbom1 = await store_sbom(db_session, project_id, CYCLONEDX_SAMPLE)
    sbom2 = await store_sbom(db_session, project_id, CYCLONEDX_SAMPLE)
    assert sbom1.id == sbom2.id


@pytest.mark.asyncio
async def test_store_sbom_unknown_format(db_session):
    project_id = uuid.UUID("00000000-0000-0000-0000-000000000004")
    db_session.add(Project(id=project_id, name="SBOM parser 4"))
    await db_session.flush()
    raw = {"unknown": True}
    sbom = await store_sbom(db_session, project_id, raw)
    assert sbom.format is None
    assert sbom.dependency_count == 0


def test_extract_service_name_present():
    raw = {"metadata": {"component": {"name": "  my-service  "}}}
    assert _extract_service_name(raw) == "my-service"


def test_extract_service_name_missing():
    assert _extract_service_name({}) is None
    assert _extract_service_name({"metadata": {"component": {"name": "  "}}}) is None


@pytest.mark.asyncio
async def test_store_sbom_creates_service_from_metadata(db_session):
    project_id = uuid.UUID("00000000-0000-0000-0000-000000000005")
    db_session.add(Project(id=project_id, name="SBOM parser 5"))
    await db_session.flush()

    raw = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"name": "auto-service"}},
        "components": [],
    }
    sbom = await store_sbom(db_session, project_id, raw)
    assert sbom.service_id is not None

    from models.service import Service

    service = (
        await db_session.execute(select(Service).where(Service.id == sbom.service_id))
    ).scalar_one()
    assert service.name == "auto-service"


def test_extract_timestamp_invalid():
    assert _extract_timestamp({"metadata": {"timestamp": "not-a-date"}}) is None
    assert _extract_timestamp({}) is None
    assert _extract_timestamp({"metadata": {"timestamp": "2026-01-15T10:00:00Z"}}) is not None
