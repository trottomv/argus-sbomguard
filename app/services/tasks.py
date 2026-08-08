import asyncio
import logging
import uuid
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
from services.vulnerability_scanner import (
    reconcile_vulnerabilities,
    retire_stale_vulnerabilities,
    scan_with_grype,
)

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


async def _do_scan_sbom(db: AsyncSession, sbom_id: str) -> None:
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
    await retire_stale_vulnerabilities(db, sbom, {v.get("id") for v in scan_results if v.get("id")})
    await reconcile_vulnerabilities(db, sbom)
    await db.commit()

    logger.info("Scanned SBOM %s: %d deps", sbom_id, sbom.dependency_count or 0)


async def _latest_sbom_ids(db: AsyncSession) -> list[uuid.UUID]:
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


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

MAX_ALERT_DELIVERY_ATTEMPTS = 5


def _severity_rank(value: str | None) -> int:
    return _SEVERITY_RANK.get((value or "unknown").lower(), 99)


async def _open_vulnerabilities(
    db: AsyncSession,
) -> tuple[dict[uuid.UUID, Vulnerability], dict[uuid.UUID, dict[uuid.UUID, list[uuid.UUID]]]]:
    """Return open vulnerabilities and, per vulnerability, its open link ids grouped by project.

    Link ids are selected directly (no SELECT DISTINCT over the entity),
    because the Vulnerability entity carries JSON columns (affected_packages,
    extra_data, ...) that PostgreSQL cannot equate.
    """
    rows = await db.execute(
        select(SBOMVulnerability.id, SBOMVulnerability.vulnerability_id, SBOM.project_id)
        .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
        .where(SBOMVulnerability.status == "open")
    )
    vuln_ids: set[uuid.UUID] = set()
    links_by_vuln: dict[uuid.UUID, dict[uuid.UUID, list[uuid.UUID]]] = {}
    for link_id, vuln_id, project_id in rows.all():
        vuln_ids.add(vuln_id)
        links_by_vuln.setdefault(vuln_id, {}).setdefault(project_id, []).append(link_id)

    if not vuln_ids:
        return {}, {}

    vulns = await db.execute(select(Vulnerability).where(Vulnerability.id.in_(vuln_ids)))
    return {v.id: v for v in vulns.scalars().all()}, links_by_vuln


async def _enabled_alerts(db: AsyncSession) -> list[AlertConfig]:
    result = await db.execute(select(AlertConfig).where(AlertConfig.enabled))
    return list(result.scalars().all())


async def _deliver(alert: AlertConfig, vuln: Vulnerability) -> tuple[str, bool]:
    """Send the alert, returning ``(channel, success)``."""
    message = f"🔴 *{vuln.cve_id}* ({vuln.severity})\n{vuln.summary}"
    if alert.notification_type == "slack" and settings.slack_webhook_url:
        return "slack", await send_slack(settings.slack_webhook_url, message)
    if alert.notification_type == "email":
        recipients = alert.config.get("to") or ", ".join(settings.alert_email_recipients)
        if not recipients:
            return "email", False
        return "email", await send_email(
            recipients,
            f"Critical: {vuln.cve_id}",
            message,
        )
    return alert.notification_type, False


def _in_current_episode(n: Notification, open_ids: set[str]) -> bool:
    """True when a notification belongs to the current open episode.

    Rows without episode_link_ids are legacy (pre-episode) deliveries and are
    treated as permanently current, preserving the old dedup for existing data.
    """
    return not n.episode_link_ids or any(link_id in open_ids for link_id in n.episode_link_ids)


def _already_delivered(notifications: list[Notification], open_ids: set[str]) -> bool:
    """True when this pair was already delivered in the current episode."""
    return any(n.status != "failed" and _in_current_episode(n, open_ids) for n in notifications)


def _episode_attempts(notifications: list[Notification], open_ids: set[str]) -> list[int]:
    """Retry counts belonging to the current episode (failed attempts only)."""
    return [
        n.attempts
        for n in notifications
        if n.status == "failed" and _in_current_episode(n, open_ids)
    ]


async def _do_check_alerts(db: AsyncSession) -> None:
    vulns, links_by_vuln = await _open_vulnerabilities(db)
    alerts = await _enabled_alerts(db)
    if not vulns or not alerts:
        return

    notifications = await db.execute(
        select(Notification).where(
            Notification.vulnerability_id.in_(list(vulns)),
            Notification.alert_config_id.in_([a.id for a in alerts]),
        )
    )
    by_pair: dict[tuple[uuid.UUID, uuid.UUID], list[Notification]] = {}
    for n in notifications.scalars().all():
        by_pair.setdefault((n.vulnerability_id, n.alert_config_id), []).append(n)

    for alert in alerts:
        for vuln_id, projects in links_by_vuln.items():
            open_link_ids = projects.get(alert.project_id)
            if not open_link_ids:
                continue
            vuln = vulns[vuln_id]
            if _severity_rank(vuln.severity) > _severity_rank(alert.severity_threshold):
                continue

            existing = by_pair.get((vuln_id, alert.id), [])
            open_ids = {str(link_id) for link_id in open_link_ids}
            if _already_delivered(existing, open_ids):
                continue
            current_episode_failed = [
                n for n in existing if n.status == "failed" and _in_current_episode(n, open_ids)
            ]
            attempts_so_far = [n.attempts for n in current_episode_failed]
            if attempts_so_far and max(attempts_so_far) >= MAX_ALERT_DELIVERY_ATTEMPTS:
                # Give up retrying a permanently failing delivery for this episode.
                continue

            channel, success = await _deliver(alert, vuln)
            status = "sent" if success else "failed"
            attempts = 0 if success else max(attempts_so_far, default=0) + 1
            if current_episode_failed:
                # Same-episode retry: flip the current episode's failed attempt(s)
                # to the new outcome instead of accumulating rows.
                for n in current_episode_failed:
                    n.status = status
                    n.channel = channel
                    n.attempts = attempts
                    n.sbom_vulnerability_id = min(open_link_ids)
                    n.episode_link_ids = list(open_ids)
            else:
                # New episode (reopen) or first delivery: keep history by adding
                # a fresh row tagged to this episode's open links.
                db.add(
                    Notification(
                        alert_config_id=alert.id,
                        vulnerability_id=vuln_id,
                        sbom_vulnerability_id=min(open_link_ids),
                        episode_link_ids=list(open_ids),
                        channel=channel,
                        status=status,
                        attempts=attempts,
                    )
                )

    await db.commit()


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
                            "updated_at": datetime.now(UTC),
                        },
                    )
                )
                await db.execute(stmt)

            await db.commit()

    asyncio.run(_run())
