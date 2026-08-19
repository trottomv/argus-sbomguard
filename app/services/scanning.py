import logging
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from models.sbom import SBOM
from services.vulnerability_scanner import (
    reconcile_vulnerabilities,
    retire_stale_vulnerabilities,
    scan_with_grype,
)

logger = logging.getLogger(__name__)


async def do_scan_sbom(db: AsyncSession, sbom_id: str) -> None:
    try:
        sbom_uuid = uuid.UUID(sbom_id)
    except ValueError:
        logger.warning("Invalid SBOM id %s", sbom_id)
        return

    result = await db.execute(select(SBOM).where(SBOM.id == sbom_uuid))
    sbom = result.scalar_one_or_none()
    if not sbom:
        logger.warning("SBOM %s not found", sbom_id)
        return

    scan_results = await scan_with_grype(db, sbom)
    if scan_results is None:
        logger.warning("grype scan failed for SBOM %s; skipping reconcile", sbom_id)
        return

    await db.flush()
    await retire_stale_vulnerabilities(
        db, sbom, {result.get("id") for result in scan_results if result.get("id")}
    )
    await reconcile_vulnerabilities(db, sbom)
    await db.commit()

    logger.info("Scanned SBOM %s: %d deps", sbom_id, sbom.dependency_count or 0)


async def latest_sbom_ids(db: AsyncSession) -> list[uuid.UUID]:
    """Latest SBOM id per scope (project, service), including project-level ones."""
    ranked = (
        select(
            SBOM.id,
            func.row_number()
            .over(
                partition_by=(SBOM.project_id, SBOM.service_id),
                order_by=(SBOM.uploaded_at.desc(), SBOM.id.desc()),
            )
            .label("rn"),
        )
        .where(SBOM.raw_sbom.isnot(None))
        .subquery()
    )
    result = await db.execute(select(ranked.c.id).where(ranked.c.rn == 1))
    return result.scalars().all()
