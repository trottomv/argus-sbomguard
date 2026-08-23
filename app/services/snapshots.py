from datetime import UTC, date, datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from models.project import Project
from models.sbom import SBOM, Dependency
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)


async def do_snapshot_metrics(db: AsyncSession, snapshot_date: str | None = None) -> None:
    target_date = date.fromisoformat(snapshot_date) if snapshot_date else date.today()

    result = await db.execute(select(Project.id))
    project_ids = result.scalars().all()

    for project_id in project_ids:
        if target_date == date.today():
            open_vulns = await db.execute(
                select(Vulnerability.severity)
                .join(SBOMVulnerability)
                .join(SBOM)
                .where(
                    SBOM.project_id == project_id,
                    SBOMVulnerability.status == VulnerabilityStatus.OPEN,
                )
                .distinct(Vulnerability.id)
            )
            severities = [severity.lower() for severity in open_vulns.scalars().all()]
        else:
            # For historical days, compute: all vulns created <= date - fixed before date
            total_result = await db.execute(
                select(Vulnerability.id, Vulnerability.severity)
                .join(SBOMVulnerability)
                .join(SBOM)
                .where(SBOM.project_id == project_id, func.date(SBOM.created_at) <= target_date)
                .distinct(Vulnerability.id)
            )
            total_dict = {}
            for vuln_id, severity in total_result:
                total_dict[vuln_id] = severity.lower()

            fixed_before = await db.execute(
                select(SBOMVulnerability.vulnerability_id)
                .join(SBOM)
                .where(
                    SBOM.project_id == project_id,
                    SBOMVulnerability.status == VulnerabilityStatus.FIXED,
                    SBOMVulnerability.fixed_at.isnot(None),
                    func.date(SBOMVulnerability.fixed_at) <= target_date,
                )
                .distinct()
            )
            fixed_ids = {row[0] for row in fixed_before}
            severities = [
                severity for vuln_id, severity in total_dict.items() if vuln_id not in fixed_ids
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
            select(func.count(func.distinct(SBOMVulnerability.vulnerability_id)))
            .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
            .where(
                SBOM.project_id == project_id,
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
            .where(SBOM.project_id == project_id, SBOM.created_at <= target_date)
        )
        dep_count_val = dep_count.scalar() or 0

        stmt = (
            insert(VulnerabilitySnapshot)
            .values(
                project_id=project_id,
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
                constraint="vulnerability_snapshots_project_id_snapshot_date_key",
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
