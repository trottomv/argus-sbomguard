from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
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

    # A vulnerability counts as "open" while it has at least one open link,
    # consistent with the vulnerability list. Open and fixed are independent
    # metrics: a CVE fixed on one service may still be open on another.
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
    else:
        # Historical days: vulns whose link was open on that date — detected by
        # then and either still open or fixed only after that date.
        day_end = datetime.combine(target_date, time.max, tzinfo=UTC)
        total_result = await db.execute(
            select(Vulnerability.id, Vulnerability.severity)
            .join(SBOMVulnerability)
            .where(
                SBOMVulnerability.detected_at <= day_end,
                or_(
                    SBOMVulnerability.fixed_at.is_(None),
                    SBOMVulnerability.fixed_at > day_end,
                ),
                Vulnerability.severity.isnot(None),
            )
            .distinct(Vulnerability.id)
        )
        total_dict = {row[0]: row[1] for row in total_result}

    severities = [severity.lower() for severity in total_dict.values()]

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

    if target_date == date.today():
        # Retention: keep only the last snapshot_retention_days dates on the
        # scheduled (today) path. Historical backfills are written untouched so
        # past-day data stays queryable while it is being written, but any
        # backfilled row older than the window is pruned on the next scheduled run.
        cutoff = date.today() - timedelta(days=settings.snapshot_retention_days - 1)
        await db.execute(
            delete(VulnerabilitySnapshot).where(
                VulnerabilitySnapshot.snapshot_date < cutoff,
                # Only the global (project_id IS NULL) rows are written here.
                VulnerabilitySnapshot.project_id.is_(None),
            )
        )

    await db.commit()
