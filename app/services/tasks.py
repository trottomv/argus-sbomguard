import asyncio
import logging
from datetime import UTC, date, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from celery_app import celery_app
from config import settings
from models.alert import AlertConfig, Notification
from models.project import Project
from models.sbom import SBOM, Dependency
from models.vulnerability import SBOMVulnerability, Vulnerability, VulnerabilitySnapshot
from services.notifications import send_email, send_slack
from services.vulnerability_scanner import reconcile_vulnerabilities, scan_with_grype

logger = logging.getLogger(__name__)


def _make_session():
    engine = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@celery_app.task(name="tasks.scan_sbom")
def scan_sbom(sbom_id: str):
    async def _run():
        async with _make_session()() as db:
            result = await db.execute(select(SBOM).where(SBOM.id == sbom_id))
            sbom = result.scalar_one_or_none()
            if not sbom:
                logger.warning("SBOM %s not found", sbom_id)
                return

            await scan_with_grype(db, sbom)
            await db.flush()
            await reconcile_vulnerabilities(db, sbom)
            await db.commit()

            logger.info("Scanned SBOM %s: %d deps", sbom_id, sbom.dependency_count or 0)

    asyncio.run(_run())


@celery_app.task(name="tasks.check_alerts")
def check_alerts():
    async def _run():
        async with _make_session()() as db:
            result = await db.execute(
                select(Vulnerability)
                .join(SBOMVulnerability)
                .filter(SBOMVulnerability.status == "open")
                .distinct()
            )
            vulns = result.scalars().all()

            alert_result = await db.execute(select(AlertConfig).where(AlertConfig.enabled))
            alerts = alert_result.scalars().all()

            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

            for vuln in vulns:
                vuln_severity = severity_order.get(
                    vuln.severity.lower() if vuln.severity else "unknown", 99
                )

                for alert in alerts:
                    threshold = severity_order.get(alert.severity_threshold.lower(), 1)
                    if vuln_severity > threshold:
                        continue

                    already_notified = await db.execute(
                        select(Notification).where(
                            Notification.vulnerability_id == vuln.id,
                            Notification.alert_config_id == alert.id,
                        )
                    )
                    if already_notified.scalar_one_or_none():
                        continue

                    msg = f"🔴 *{vuln.cve_id}* ({vuln.severity})\n{vuln.summary}"

                    notification_channel = alert.notification_type
                    if notification_channel == "slack" and settings.slack_webhook_url:
                        success = await send_slack(settings.slack_webhook_url, msg)
                    elif notification_channel == "email":
                        success = await send_email(
                            alert.config.get("to", ""),
                            f"Critical: {vuln.cve_id}",
                            msg,
                        )
                    else:
                        success = False

                    notif = Notification(
                        alert_config_id=alert.id,
                        vulnerability_id=vuln.id,
                        channel=notification_channel,
                        status="sent" if success else "failed",
                    )
                    db.add(notif)

            await db.commit()

    asyncio.run(_run())


@celery_app.task(name="tasks.snapshot_metrics")
def snapshot_metrics(snapshot_date: str | None = None):
    target_date = date.fromisoformat(snapshot_date) if snapshot_date else date.today()

    async def _run():
        async with _make_session()() as db:
            result = await db.execute(select(Project.id))
            project_ids = result.scalars().all()

            for pid in project_ids:
                if target_date == date.today():
                    open_vulns = await db.execute(
                        select(Vulnerability.severity)
                        .join(SBOMVulnerability)
                        .join(SBOM)
                        .where(SBOM.project_id == pid, SBOMVulnerability.status == "open")
                        .distinct(Vulnerability.id)
                    )
                    severities = [s.lower() for s in open_vulns.scalars().all()]
                else:
                    # For historical days, compute: all vulns created <= date - fixed before date
                    total_result = await db.execute(
                        select(Vulnerability.id, Vulnerability.severity)
                        .join(SBOMVulnerability)
                        .join(SBOM)
                        .where(SBOM.project_id == pid, func.date(SBOM.created_at) <= target_date)
                        .distinct(Vulnerability.id)
                    )
                    total_dict = {}
                    for v_id, sev in total_result:
                        total_dict[v_id] = sev.lower()

                    fixed_before = await db.execute(
                        select(SBOMVulnerability.vulnerability_id)
                        .join(SBOM)
                        .where(
                            SBOM.project_id == pid,
                            SBOMVulnerability.status == "fixed",
                            SBOMVulnerability.fixed_at.isnot(None),
                            func.date(SBOMVulnerability.fixed_at) <= target_date,
                        )
                        .distinct()
                    )
                    fixed_ids = set(r[0] for r in fixed_before)
                    severities = [sev for vid, sev in total_dict.items() if vid not in fixed_ids]

                critical_count = sum(1 for s in severities if s == "critical")
                high_count = sum(1 for s in severities if s == "high")
                medium_count = sum(1 for s in severities if s == "medium")
                low_count = sum(1 for s in severities if s == "low")

                fixed_result = await db.execute(
                    select(func.count(SBOMVulnerability.vulnerability_id))
                    .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
                    .where(
                        SBOM.project_id == pid,
                        SBOMVulnerability.status == "fixed",
                        SBOMVulnerability.fixed_at.isnot(None),
                        func.date(SBOMVulnerability.fixed_at) <= target_date,
                    )
                )
                fixed_val = fixed_result.scalar() or 0

                dep_count = await db.execute(
                    select(func.count(Dependency.id))
                    .select_from(SBOM)
                    .join(Dependency, Dependency.sbom_id == SBOM.id)
                    .where(SBOM.project_id == pid, SBOM.created_at <= target_date)
                )
                dep_count_val = dep_count.scalar() or 0

                from sqlalchemy.dialects.postgresql import insert

                stmt = (
                    insert(VulnerabilitySnapshot)
                    .values(
                        project_id=pid,
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
                            "created_at": datetime.now(UTC),
                        },
                    )
                )
                await db.execute(stmt)

            await db.commit()

    asyncio.run(_run())
