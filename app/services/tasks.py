import asyncio
import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from celery_app import celery_app
from config import settings
from services.alerting import do_check_alerts as _do_check_alerts
from services.scanning import do_scan_sbom as _do_scan_sbom
from services.scanning import latest_sbom_ids as _latest_sbom_ids
from services.snapshots import do_snapshot_metrics as _do_snapshot_metrics

logger = logging.getLogger(__name__)


def _make_session():
    engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@celery_app.task(name="tasks.scan_sbom")
def scan_sbom(sbom_id: str):
    async def _run():
        async with _make_session()() as db:
            await _do_scan_sbom(db, sbom_id)

    asyncio.run(_run())


@celery_app.task(name="tasks.rescan_vulnerabilities")
def rescan_vulnerabilities():
    """Rescan the latest SBOM of every service of every project.

    New vulnerabilities are published daily, so periodically re-running grype on
    the current SBOMs keeps the data fresh. Duplicates are prevented by the
    ``cve_id`` unique index and the ``sbom_vulnerabilities`` composite PK, and
    findings grype no longer reports are retired on each run.
    """

    async def _run():
        async with _make_session()() as db:
            sbom_ids = await _latest_sbom_ids(db)
            logger.info("Rescanning %d latest SBOMs", len(sbom_ids))
            for sbom_id in sbom_ids:
                scan_sbom.delay(str(sbom_id))

    asyncio.run(_run())


@celery_app.task(name="tasks.check_alerts")
def check_alerts():
    async def _run():
        async with _make_session()() as db:
            await _do_check_alerts(db)

    asyncio.run(_run())


@celery_app.task(name="tasks.snapshot_metrics")
def snapshot_metrics(snapshot_date: str | None = None):
    async def _run():
        async with _make_session()() as db:
            await _do_snapshot_metrics(db, snapshot_date)

    asyncio.run(_run())
