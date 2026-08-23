from datetime import UTC, date, datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from models.sbom import SBOM, Dependency
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)


async def do_snapshot_metrics(db: AsyncSession, snapshot_date: str | None = None) -> None:
    """Store a platform-wide daily snapshot of distinct vulnerability counts.

    Counts are distinct across all projects: a vulnerability present in several
    projects (or linked to several packages of the same SBOM) is counted once,
    consistent with the dashboard cards. The row is keyed by ``snapshot_date``
    with ``project_id`` NULL.
    """
    target_date = date.fromisoformat(snapshot_date) if snapshot_date else date.today()

    # A vulnerability is "open" only while it is not fixed anywhere (fixed wins):
    # this keeps open and fixed disjoint and makes today and historical paths agree.
    if target_date == date.today():
        total_result = await db.execute(
            select(Vulnerability.id, Vulnerability.severity)
            .join(SBOMVulnerability)
            .where(
                SBOMVulnerability.status == VulnerabilityStatus.OPEN,
                Vulnerability.severity.isnot(None),
            )
            .distinct(Vulnerability.id)
        )
        total_dict = {row[0]: row[1] for row in total_result}

        fixed_before = await db.execute(
            select(SBOMVulnerability.vulnerability_id)
            .where(
                SBOMVulnerability.status == VulnerabilityStatus.FIXED,
                SBOMVulnerability.fixed_at.isnot(None),
            )
            .distinct()
        )
    else:
        # For historical days, compute: all vulns created <= date - fixed before date
        total_result = await db.execute(
            select(Vulnerability.id, Vulnerability.severity)
            .join(SBOMVulnerability)
            .join(SBOM)
            .where(
                func.date(SBOM.created_at) <= target_date,
                Vulnerability.severity.isnot(None),
            )
            .distinct(Vulnerability.id)
        )
        total_dict = {row[0]: row[1] for row in total_result}

        fixed_before = await db.execute(
            select(SBOMVulnerability.vulnerability_id)
            .where(
                SBOMVulnerability.status == VulnerabilityStatus.FIXED,
                SBOMVulnerability.fixed_at.isnot(None),
                func.date(SBOMVulnerability.fixed_at) <= target_date,
            )
            .distinct()
        )

    fixed_ids = {row[0] for row in fixed_before}
    severities = [
        severity.lower() for vuln_id, severity in total_dict.items() if vuln_id not in fixed_ids
    ]

    critical_count = sum(
        1 for severity in severities if severity == VulnerabilitySeverity.CRITICAL.value.lower()
    )
    high_count = sum(
        1 for severity in severities if severity == VulnerabilitySeverity.HIGH.value.lower()
    )
    medium_count = sum(
        1 for severity in severities if severity == VulnerabilitySeverity.MEDIUM.value.lower()
    )
    low_count = sum(
        1 for severity in severities if severity == VulnerabilitySeverity.LOW.value.lower()
    )

    fixed_result = await db.execute(
        select(func.count(func.distinct(SBOMVulnerability.vulnerability_id))).where(
            SBOMVulnerability.status == VulnerabilityStatus.FIXED,
            SBOMVulnerability.fixed_at.isnot(None),
            func.date(SBOMVulnerability.fixed_at) <= target_date,
        )
    )
    fixed_val = fixed_result.scalar() or 0

    dep_count = await db.execute(
        select(func.count(Dependency.id))
        .select_from(SBOM)
        .join(Dependency, Dependency.sbom_id == SBOM.id)
        .where(SBOM.created_at <= target_date)
    )
    dep_count_val = dep_count.scalar() or 0

    stmt = (
        insert(VulnerabilitySnapshot)
        .values(
            project_id=None,
            snapshot_date=target_date,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            fixed_count=fixed_val,
            total_dependencies=dep_count_val,
            created_at=datetime.now(UTC),
        )
        .on_conflict_do_update(
            index_elements=[VulnerabilitySnapshot.snapshot_date],
            index_where=VulnerabilitySnapshot.project_id.is_(None),
            set_={
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "fixed_count": fixed_val,
                "total_dependencies": dep_count_val,
                "metrics": {},
                "updated_at": datetime.now(UTC),
            },
        )
    )
    await db.execute(stmt)

    await db.commit()
