import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from models.project import Project
from models.sbom import SBOM
from models.service import Service
from models.vulnerability import SBOMVulnerability, Vulnerability
from services.tasks import _do_scan_sbom, _latest_sbom_ids


@pytest.mark.asyncio
async def test_latest_sbom_ids_picks_latest_per_scope(db_session):
    p1 = uuid.uuid4()
    p2 = uuid.uuid4()
    s1 = uuid.uuid4()
    s2 = uuid.uuid4()

    db_session.add_all(
        [Project(id=p1, name="Tasks project 1"), Project(id=p2, name="Tasks project 2")]
    )
    db_session.add_all(
        [
            Service(id=s1, project_id=p1, name="Tasks service 1"),
            Service(id=s2, project_id=p1, name="Tasks service 2"),
        ]
    )

    sboms = [
        SBOM(
            project_id=p1,
            service_id=s1,
            format="cyclonedx",
            raw_sbom={"v": "1"},
            sha256="a" * 64,
            uploaded_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        SBOM(
            project_id=p1,
            service_id=s1,
            format="cyclonedx",
            raw_sbom={"v": "2"},
            sha256="b" * 64,
            uploaded_at=datetime(2026, 1, 2, tzinfo=UTC),
        ),
        SBOM(
            project_id=p1,
            service_id=s2,
            format="cyclonedx",
            raw_sbom={"v": "1"},
            sha256="c" * 64,
            uploaded_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        SBOM(
            project_id=p1,
            format="cyclonedx",
            raw_sbom={"v": "1"},
            sha256="d" * 64,
            uploaded_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        SBOM(
            project_id=p2,
            format="cyclonedx",
            raw_sbom={"v": "1"},
            sha256="e" * 64,
            uploaded_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        SBOM(
            project_id=p2,
            format="cyclonedx",
            raw_sbom={"v": "2"},
            sha256="f" * 64,
            uploaded_at=datetime(2026, 1, 3, tzinfo=UTC),
        ),
    ]
    db_session.add_all(sboms)
    await db_session.commit()

    result = await _latest_sbom_ids(db_session)

    assert set(result) == {sboms[1].id, sboms[2].id, sboms[3].id, sboms[5].id}
    assert sboms[0].id not in result  # superseded by a newer SBOM for service s1
    assert sboms[4].id not in result  # superseded by a newer project-level SBOM for p2


async def _make_scope(db_session, project_id, older_uploaded, latest_uploaded):
    db_session.add(Project(id=project_id, name=f"Tasks project {project_id}"))
    older = SBOM(
        project_id=project_id,
        format="cyclonedx",
        raw_sbom={"v": "1"},
        sha256=uuid.uuid4().hex,
        uploaded_at=older_uploaded,
    )
    latest = SBOM(
        project_id=project_id,
        format="cyclonedx",
        raw_sbom={"v": "2"},
        sha256=uuid.uuid4().hex,
        uploaded_at=latest_uploaded,
    )
    db_session.add_all([older, latest])
    await db_session.flush()

    vuln = Vulnerability(cve_id="CVE-2026-0001", source="grype", severity="HIGH")
    db_session.add(vuln)
    await db_session.flush()

    link = SBOMVulnerability(
        sbom_id=older.id,
        dependency_purl="pkg:npm/example@1.0.0",
        vulnerability_id=vuln.id,
        status="open",
        detected_at=datetime.now(UTC),
    )
    db_session.add(link)
    await db_session.commit()
    return older, latest, vuln, link


@pytest.mark.asyncio
async def test_do_scan_sbom_skips_reconcile_when_scan_fails(db_session):
    project_id = uuid.uuid4()
    older, latest, _, _ = await _make_scope(
        db_session,
        project_id,
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 2, tzinfo=UTC),
    )

    with patch("services.tasks.scan_with_grype", new_callable=AsyncMock, return_value=None):
        await _do_scan_sbom(db_session, str(latest.id))

    fresh = (
        await db_session.execute(
            select(SBOMVulnerability).where(SBOMVulnerability.sbom_id == older.id)
        )
    ).scalar_one()
    assert fresh.status == "open"


@pytest.mark.asyncio
async def test_do_scan_sbom_reconciles_on_success(db_session):
    project_id = uuid.uuid4()
    older, latest, _, _ = await _make_scope(
        db_session,
        project_id,
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 2, tzinfo=UTC),
    )

    with patch("services.tasks.scan_with_grype", new_callable=AsyncMock, return_value=[]):
        await _do_scan_sbom(db_session, str(latest.id))

    fresh = (
        await db_session.execute(
            select(SBOMVulnerability).where(SBOMVulnerability.sbom_id == older.id)
        )
    ).scalar_one()
    assert fresh.status == "fixed"


@pytest.mark.asyncio
async def test_do_scan_sbom_retires_stale_vulns_on_latest(db_session):
    project_id = uuid.uuid4()
    _, latest, _, _ = await _make_scope(
        db_session,
        project_id,
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 2, tzinfo=UTC),
    )

    stale = Vulnerability(cve_id="CVE-2026-0009", source="grype", severity="LOW")
    db_session.add(stale)
    await db_session.flush()
    stale_link = SBOMVulnerability(
        sbom_id=latest.id,
        dependency_purl="pkg:npm/stale@2.0.0",
        vulnerability_id=stale.id,
        status="open",
        detected_at=datetime.now(UTC),
    )
    db_session.add(stale_link)
    await db_session.commit()

    with patch(
        "services.tasks.scan_with_grype",
        new_callable=AsyncMock,
        return_value=[{"id": "CVE-2026-9999"}],
    ):
        await _do_scan_sbom(db_session, str(latest.id))

    stale_fresh = (
        await db_session.execute(
            select(SBOMVulnerability).where(
                SBOMVulnerability.sbom_id == latest.id,
                SBOMVulnerability.dependency_purl == "pkg:npm/stale@2.0.0",
            )
        )
    ).scalar_one()
    assert stale_fresh.status == "fixed"
