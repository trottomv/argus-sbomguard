from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models.sbom import SBOM, Dependency
from models.vulnerability import SBOMVulnerability, VulnerabilitySnapshot


async def prune_snapshots(db: AsyncSession) -> None:
    """Prune global snapshots older than ``snapshot_retention_days``.

    Snapshot retention is always on: the dashboard chart renders this window.
    """
    cutoff = date.today() - timedelta(days=settings.snapshot_retention_days - 1)
    await db.execute(
        delete(VulnerabilitySnapshot).where(
            VulnerabilitySnapshot.snapshot_date < cutoff,
            VulnerabilitySnapshot.project_id.is_(None),
        )
    )
    await db.commit()


async def prune_sboms(db: AsyncSession) -> None:
    """Prune SBOMs older than ``sbom_retention_days``.

    Keeps the latest SBOM per (project, service) scope as a safety net so a
    service is never emptied. Retention is disabled when ``sbom_retention_days``
    is ``None`` (set via ``0`` or an empty value).
    """
    if settings.sbom_retention_days is None:
        return

    sbom_cutoff = datetime.combine(
        date.today() - timedelta(days=settings.sbom_retention_days), time.min, tzinfo=UTC
    )
    ranked = select(
        SBOM.id,
        SBOM.created_at,
        func.row_number()
        .over(
            partition_by=(SBOM.project_id, SBOM.service_id),
            order_by=(SBOM.uploaded_at.desc(), SBOM.id.desc()),
        )
        .label("rn"),
    ).subquery()
    target = (
        select(ranked.c.id)
        .where(
            ranked.c.rn > 1,
            ranked.c.created_at < sbom_cutoff,
        )
        .scalar_subquery()
    )

    # The FKs from sbom_vulnerabilities/dependencies to sboms have no
    # ON DELETE CASCADE, so remove children first (mirrors the ORM cascade
    # used by the SBOM delete endpoint).
    await db.execute(delete(SBOMVulnerability).where(SBOMVulnerability.sbom_id.in_(target)))
    await db.execute(delete(Dependency).where(Dependency.sbom_id.in_(target)))
    await db.execute(delete(SBOM).where(SBOM.id.in_(target)))

    await db.commit()


async def do_prune_old_data(db: AsyncSession) -> None:
    """Prune expired snapshots and SBOMs on a schedule."""
    await prune_snapshots(db)
    await prune_sboms(db)
