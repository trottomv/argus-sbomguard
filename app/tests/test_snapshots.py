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
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id == project.id)
        )
    ).scalar_one()
    assert snap.snapshot_date == past
    assert snap.medium_count == 0  # fixed before the snapshot date
    assert snap.fixed_count == 1
    assert snap.total_dependencies == 1


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
                select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id == project.id)
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
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id == project.id)
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
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id == project.id)
        )
    ).scalar_one()
    assert snap.fixed_count == 1
