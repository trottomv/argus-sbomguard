import asyncio
import logging
from datetime import UTC, date, datetime

from sqlalchemy import func, select

from app.celery_app import celery_app
from app.config import settings
from app.database import async_session_factory
from app.models.alert import AlertConfig, Notification
from app.models.project import Project
from app.models.sbom import SBOM, Dependency
from app.models.vulnerability import SBOMVulnerability, Vulnerability, VulnerabilitySnapshot
from app.services.notifications import send_email, send_slack
from app.services.vulnerability_scanner import scan_with_grype

logger = logging.getLogger(__name__)


@celery_app.task(name="tasks.scan_sbom")
def scan_sbom(sbom_id: str):
    async def _run():
        async with async_session_factory() as db:
            result = await db.execute(select(SBOM).where(SBOM.id == sbom_id))
            sbom = result.scalar_one_or_none()
            if not sbom:
                logger.warning("SBOM %s not found", sbom_id)
                return

            await scan_with_grype(db, sbom)
            await db.commit()

    asyncio.run(_run())


@celery_app.task(name="tasks.check_alerts")
def check_alerts():
    async def _run():
        async with async_session_factory() as db:
            result = await db.execute(
                select(Vulnerability)
                .join(SBOMVulnerability)
                .filter(SBOMVulnerability.status == "open")
                .distinct(Vulnerability.id)
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
def snapshot_metrics():
    async def _run():
        async with async_session_factory() as db:
            result = await db.execute(select(Project.id))
            project_ids = result.scalars().all()

            for pid in project_ids:
                counts = await db.execute(
                    select(
                        func.count()
                        .filter(Vulnerability.severity.ilike("critical"))
                        .label("critical"),
                        func.count().filter(Vulnerability.severity.ilike("high")).label("high"),
                        func.count().filter(Vulnerability.severity.ilike("medium")).label("medium"),
                        func.count().filter(Vulnerability.severity.ilike("low")).label("low"),
                    )
                    .select_from(Vulnerability)
                    .join(SBOMVulnerability)
                    .join(SBOM)
                    .where(SBOM.project_id == pid, SBOMVulnerability.status == "open")
                )
                row = counts.one()

                dep_count = await db.execute(
                    select(func.count(Dependency.id))
                    .select_from(SBOM)
                    .join(Dependency, Dependency.sbom_id == SBOM.id)
                    .where(SBOM.project_id == pid)
                )
                dep_count_val = dep_count.scalar() or 0

                snapshot = VulnerabilitySnapshot(
                    project_id=pid,
                    snapshot_date=date.today(),
                    critical_count=row.critical or 0,
                    high_count=row.high or 0,
                    medium_count=row.medium or 0,
                    low_count=row.low or 0,
                    total_dependencies=dep_count_val,
                    created_at=datetime.now(UTC),
                )
                db.add(snapshot)

            await db.commit()

    asyncio.run(_run())
