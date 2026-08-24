from datetime import UTC, date, datetime

import pytest
from sqlalchemy import select

from models.project import Project
from models.sbom import SBOM, Dependency, SBOMFormat
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)
from services.snapshots import do_snapshot_metrics


@pytest.mark.asyncio
async def test_snapshot_metrics_historical_date(db_session):
    project = Project(name="historical-snapshot")
    db_session.add(project)
    await db_session.flush()

    past = date(2026, 1, 15)
    sbom = SBOM(
        project_id=project.id,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="7" * 64,
        created_at=datetime(2026, 1, 10, tzinfo=UTC),
    )
    db_session.add(sbom)
    await db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2026-9101", source="grype", severity=VulnerabilitySeverity.MEDIUM
    )
    db_session.add(vuln)
    await db_session.flush()
    db_session.add(
        Dependency(sbom_id=sbom.id, name="hist", version="1.0.0", purl="pkg:npm/hist@1.0.0")
    )
    link = SBOMVulnerability(
        sbom_id=sbom.id,
        dependency_purl="pkg:npm/hist@1.0.0",
        vulnerability_id=vuln.id,
        status=VulnerabilityStatus.FIXED,
        detected_at=datetime(2026, 1, 11, tzinfo=UTC),
        fixed_at=datetime(2026, 1, 12, tzinfo=UTC),
    )
    db_session.add(link)
    await db_session.commit()

    await do_snapshot_metrics(db_session, past.isoformat())

    snap = (
        await db_session.execute(
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id.is_(None))
        )
    ).scalar_one()
    assert snap.snapshot_date == past
    assert snap.medium_count == 0  # fixed before the snapshot date
    assert snap.fixed_count == 1
    assert snap.total_dependencies == 1


@pytest.mark.asyncio
async def test_snapshot_metrics_historical_open_until_fix(db_session):
    project = Project(name="historical-asof")
    db_session.add(project)
    await db_session.flush()

    sbom = SBOM(
        project_id=project.id,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="8" * 64,
        created_at=datetime(2026, 1, 10, tzinfo=UTC),
    )
    db_session.add(sbom)
    await db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2026-9102", source="grype", severity=VulnerabilitySeverity.MEDIUM
    )
    db_session.add(vuln)
    await db_session.flush()
    db_session.add(
        Dependency(sbom_id=sbom.id, name="asof", version="1.0.0", purl="pkg:npm/asof@1.0.0")
    )
    db_session.add(
        SBOMVulnerability(
            sbom_id=sbom.id,
            dependency_purl="pkg:npm/asof@1.0.0",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.FIXED,
            detected_at=datetime(2026, 1, 10, tzinfo=UTC),
            fixed_at=datetime(2026, 1, 13, tzinfo=UTC),
        )
    )
    await db_session.commit()

    # Open from Jan 10 until fixed on Jan 13: counted on Jan 11, not on Jan 15
    await do_snapshot_metrics(db_session, "2026-01-11")
    snap = (
        await db_session.execute(
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id.is_(None))
        )
    ).scalar_one()
    assert snap.medium_count == 1
    assert snap.fixed_count == 0

    await do_snapshot_metrics(db_session, "2026-01-15")
    snaps = (
        (
            await db_session.execute(
                select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id.is_(None))
            )
        )
        .scalars()
        .all()
    )
    later = next(s for s in snaps if s.snapshot_date == date(2026, 1, 15))
    assert later.medium_count == 0
    assert later.fixed_count == 1


@pytest.mark.asyncio
async def test_snapshot_metrics_upsert_existing(db_session):
    project = Project(name="upsert-snapshot")
    db_session.add(project)
    await db_session.flush()

    past = date(2026, 2, 1)
    sbom = SBOM(
        project_id=project.id,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="6" * 64,
        created_at=datetime(2026, 1, 20, tzinfo=UTC),
    )
    db_session.add(sbom)
    await db_session.commit()

    await do_snapshot_metrics(db_session, past.isoformat())
    await do_snapshot_metrics(db_session, past.isoformat())

    snaps = (
        (
            await db_session.execute(
                select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id.is_(None))
            )
        )
        .scalars()
        .all()
    )
    assert len(snaps) == 1


@pytest.mark.asyncio
async def test_snapshot_metrics_counts_open_severities(db_session):
    project = Project(name="snapshot-test")
    db_session.add(project)
    await db_session.flush()

    sbom = SBOM(
        project_id=project.id,
        version="v1",
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="9" * 64,
    )
    db_session.add(sbom)
    await db_session.flush()

    vulns = [
        Vulnerability(
            cve_id="CVE-2026-9001", source="grype", severity=VulnerabilitySeverity.CRITICAL
        ),
        Vulnerability(cve_id="CVE-2026-9002", source="grype", severity=VulnerabilitySeverity.HIGH),
    ]
    db_session.add_all(vulns)
    await db_session.flush()

    for idx, vuln in enumerate(vulns):
        db_session.add(
            SBOMVulnerability(
                sbom_id=sbom.id,
                dependency_purl=f"pkg:npm/dep{idx}@1.0.0",
                vulnerability_id=vuln.id,
                status=VulnerabilityStatus.OPEN,
                detected_at=datetime.now(UTC),
            )
        )
    await db_session.commit()

    await do_snapshot_metrics(db_session, date.today().isoformat())

    snap = (
        await db_session.execute(
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id.is_(None))
        )
    ).scalar_one()
    assert snap.critical_count == 1
    assert snap.high_count == 1
    assert snap.medium_count == 0
    assert snap.low_count == 0
    assert snap.fixed_count == 0


@pytest.mark.asyncio
async def test_snapshot_metrics_fixed_count_deduplicates_by_vulnerability(db_session):
    project = Project(name="fixed-dedup")
    db_session.add(project)
    await db_session.flush()

    past = date(2026, 3, 1)
    sboms = [
        SBOM(
            project_id=project.id,
            version=f"v{i}",
            format=SBOMFormat.CYCLONEDX,
            raw_sbom={"bomFormat": "CycloneDX"},
            sha256=str(i) * 64,
            created_at=datetime(2026, 2, 10, tzinfo=UTC),
        )
        for i in range(2)
    ]
    db_session.add_all(sboms)
    await db_session.flush()

    vuln = Vulnerability(cve_id="CVE-2026-9501", source="grype", severity=VulnerabilitySeverity.LOW)
    db_session.add(vuln)
    await db_session.flush()

    for i, sbom in enumerate(sboms):
        db_session.add(
            SBOMVulnerability(
                sbom_id=sbom.id,
                dependency_purl=f"pkg:npm/dep{i}@1.0.0",
                vulnerability_id=vuln.id,
                status=VulnerabilityStatus.FIXED,
                detected_at=datetime(2026, 2, 11, tzinfo=UTC),
                fixed_at=datetime(2026, 2, 12, tzinfo=UTC),
            )
        )
    await db_session.commit()

    await do_snapshot_metrics(db_session, past.isoformat())

    snap = (
        await db_session.execute(
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id.is_(None))
        )
    ).scalar_one()
    assert snap.fixed_count == 1


@pytest.mark.asyncio
async def test_snapshot_metrics_global_distinct_across_projects(db_session):
    projects = [Project(name=f"global-{i}") for i in range(2)]
    db_session.add_all(projects)
    await db_session.flush()

    past = date(2026, 4, 1)
    sboms = [
        SBOM(
            project_id=project.id,
            format=SBOMFormat.CYCLONEDX,
            raw_sbom={"bomFormat": "CycloneDX"},
            sha256=f"p{i}" * 32,
            created_at=datetime(2026, 3, 10, tzinfo=UTC),
        )
        for i, project in enumerate(projects)
    ]
    db_session.add_all(sboms)
    await db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2026-9601", source="grype", severity=VulnerabilitySeverity.CRITICAL
    )
    db_session.add(vuln)
    await db_session.flush()

    for i, sbom in enumerate(sboms):
        db_session.add(
            SBOMVulnerability(
                sbom_id=sbom.id,
                dependency_purl=f"pkg:npm/dep{i}@1.0.0",
                vulnerability_id=vuln.id,
                status=VulnerabilityStatus.OPEN,
                detected_at=datetime(2026, 3, 11, tzinfo=UTC),
            )
        )
    await db_session.commit()

    await do_snapshot_metrics(db_session, past.isoformat())

    snaps = (
        (
            await db_session.execute(
                select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id.is_(None))
            )
        )
        .scalars()
        .all()
    )
    assert len(snaps) == 1
    # Same CVE open in two projects is counted once platform-wide
    assert snaps[0].critical_count == 1
    assert snaps[0].fixed_count == 0


@pytest.mark.asyncio
async def test_snapshot_metrics_open_anywhere_with_fixed_elsewhere(db_session):
    projects = [Project(name=f"fw-{i}") for i in range(2)]
    db_session.add_all(projects)
    await db_session.flush()

    sboms = [
        SBOM(
            project_id=project.id,
            format=SBOMFormat.CYCLONEDX,
            raw_sbom={"bomFormat": "CycloneDX"},
            sha256=f"f{i}" * 32,
        )
        for i, project in enumerate(projects)
    ]
    db_session.add_all(sboms)
    await db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2026-9701", source="grype", severity=VulnerabilitySeverity.CRITICAL
    )
    db_session.add(vuln)
    await db_session.flush()

    db_session.add(
        SBOMVulnerability(
            sbom_id=sboms[0].id,
            dependency_purl="pkg:npm/a@1.0.0",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )
    db_session.add(
        SBOMVulnerability(
            sbom_id=sboms[1].id,
            dependency_purl="pkg:npm/b@1.0.0",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.FIXED,
            detected_at=datetime.now(UTC),
            fixed_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    await do_snapshot_metrics(db_session, date.today().isoformat())

    snap = (
        await db_session.execute(
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id.is_(None))
        )
    ).scalar_one()
    # Open in one service but fixed in another: still counted as open,
    # and also counted in the fixed metric (they are independent)
    assert snap.critical_count == 1
    assert snap.fixed_count == 1


@pytest.mark.asyncio
async def test_snapshot_metrics_null_severity_ignored(db_session):
    project = Project(name="null-sev")
    db_session.add(project)
    await db_session.flush()

    sbom = SBOM(
        project_id=project.id,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="n" * 64,
    )
    db_session.add(sbom)
    await db_session.flush()

    vuln = Vulnerability(cve_id="CVE-2026-9801", source="grype", severity=None)
    db_session.add(vuln)
    await db_session.flush()
    db_session.add(
        SBOMVulnerability(
            sbom_id=sbom.id,
            dependency_purl="pkg:npm/c@1.0.0",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    await do_snapshot_metrics(db_session, date.today().isoformat())

    snap = (
        await db_session.execute(
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id.is_(None))
        )
    ).scalar_one()
    assert snap.critical_count == 0
    assert snap.high_count == 0
    assert snap.medium_count == 0
    assert snap.low_count == 0
    assert snap.fixed_count == 0
