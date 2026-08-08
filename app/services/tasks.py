import asyncio
import logging
import uuid
from datetime import UTC, date, datetime
from enum import StrEnum

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from celery_app import celery_app
from config import settings
from models.alert import AlertConfig, Notification, NotificationChannel, NotificationStatus
from models.project import Project
from models.sbom import SBOM, Dependency
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)
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
) -> tuple[
    dict[uuid.UUID, Vulnerability],
    set[tuple[uuid.UUID, uuid.UUID]],
    dict[uuid.UUID, dict[uuid.UUID, list[str]]],
]:
    """Return open vulnerabilities, the open ``(project_id, vulnerability_id)``
    pairs, and the distinct service ids each vulnerability is open in per project.

    Link ids are not selected (no SELECT DISTINCT over the entity), because the
    Vulnerability entity carries JSON columns (affected_packages, extra_data,
    ...) that PostgreSQL cannot equate.
    """
    rows = await db.execute(
        select(SBOMVulnerability.vulnerability_id, SBOM.project_id, SBOM.service_id)
        .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
        .where(SBOMVulnerability.status == VulnerabilityStatus.OPEN)
    )
    vuln_ids: set[uuid.UUID] = set()
    open_pairs: set[tuple[uuid.UUID, uuid.UUID]] = set()
    services_by_vuln: dict[uuid.UUID, dict[uuid.UUID, set[str]]] = {}
    for vuln_id, project_id, service_id in rows.all():
        vuln_ids.add(vuln_id)
        open_pairs.add((project_id, vuln_id))
        if service_id is not None:
            services_by_vuln.setdefault(vuln_id, {}).setdefault(project_id, set()).add(
                str(service_id)
            )

    if not vuln_ids:
        return {}, set(), {}

    vulns = await db.execute(select(Vulnerability).where(Vulnerability.id.in_(vuln_ids)))
    services_map = {
        vuln_id: {project_id: sorted(services) for project_id, services in projects.items()}
        for vuln_id, projects in services_by_vuln.items()
    }
    return {v.id: v for v in vulns.scalars().all()}, open_pairs, services_map


async def _enabled_alerts(db: AsyncSession) -> list[AlertConfig]:
    result = await db.execute(select(AlertConfig).where(AlertConfig.enabled))
    return list(result.scalars().all())


async def _deliver(alert: AlertConfig, vuln: Vulnerability) -> tuple[NotificationChannel, bool]:
    """Send the alert, returning ``(channel, success)``."""
    message = f"🔴 *{vuln.cve_id}* ({vuln.severity})\n{vuln.summary}"
    if alert.notification_type == NotificationChannel.SLACK and settings.slack_webhook_url:
        return NotificationChannel.SLACK, await send_slack(settings.slack_webhook_url, message)
    if alert.notification_type == NotificationChannel.EMAIL:
        recipients = alert.config.get("to") or ", ".join(settings.alert_email_recipients)
        if not recipients:
            return NotificationChannel.EMAIL, False
        return NotificationChannel.EMAIL, await send_email(
            recipients,
            f"Critical: {vuln.cve_id}",
            message,
        )
    return alert.notification_type, False


class _DeliveryAction(StrEnum):
    SKIP = "skip"  # already delivered for the current scope
    GIVE_UP = "give_up"  # retries exhausted for this episode
    RESEND = "resend"  # affected services changed: deliver for the new set
    RETRY = "retry"  # previous attempt failed: retry in place
    DELIVER = "deliver"  # first delivery for this episode


def _delivery_action(existing: list[Notification], current_services: list[str]) -> _DeliveryAction:
    """Decide what to do for an (alert, vulnerability) pair.

    Pure decision based on the notification history and the services the
    vulnerability is currently open in. A changed service scope is always a
    fresh delivery (RESEND), even when the previous attempt failed, so the
    retry budget is reset on scope change.
    """
    active = [n for n in existing if n.status != NotificationStatus.RESOLVED]
    sent = [n for n in active if n.status == NotificationStatus.SENT]
    if sent:
        if set(sent[-1].service_ids or []) == set(current_services):
            return _DeliveryAction.SKIP
        return _DeliveryAction.RESEND

    failed = [n for n in existing if n.status == NotificationStatus.FAILED]
    if failed:
        if set(failed[-1].service_ids or []) != set(current_services):
            return _DeliveryAction.RESEND
        if max(n.attempts for n in failed) >= MAX_ALERT_DELIVERY_ATTEMPTS:
            return _DeliveryAction.GIVE_UP
        return _DeliveryAction.RETRY
    return _DeliveryAction.DELIVER


async def _load_notifications(
    db: AsyncSession, alert_by_id: dict[uuid.UUID, AlertConfig]
) -> list[Notification]:
    result = await db.execute(
        select(Notification)
        .where(Notification.alert_config_id.in_(alert_by_id))
        .order_by(Notification.created_at)
    )
    return list(result.scalars().all())


def _resolve_closed_episodes(
    notifications: list[Notification],
    alert_by_id: dict[uuid.UUID, AlertConfig],
    open_pairs: set[tuple[uuid.UUID, uuid.UUID]],
) -> None:
    """Mark notifications resolved when their vulnerability is no longer open."""
    for n in notifications:
        alert = alert_by_id.get(n.alert_config_id)
        if alert is not None and (alert.project_id, n.vulnerability_id) not in open_pairs:
            n.status = NotificationStatus.RESOLVED


def _index_by_pair(
    notifications: list[Notification],
) -> dict[tuple[uuid.UUID, uuid.UUID], list[Notification]]:
    by_pair: dict[tuple[uuid.UUID, uuid.UUID], list[Notification]] = {}
    for n in notifications:
        by_pair.setdefault((n.vulnerability_id, n.alert_config_id), []).append(n)
    return by_pair


def _record_delivery(
    db: AsyncSession,
    alert: AlertConfig,
    vuln_id: uuid.UUID,
    existing: list[Notification],
    action: _DeliveryAction,
    channel: NotificationChannel,
    success: bool,
    current_services: list[str],
) -> None:
    """Persist a delivery outcome: flip failed rows, or add a new one.

    A resend (changed service scope) closes the previous rows and adds a fresh
    one with a reset attempt budget, keeping history.
    """
    if action == _DeliveryAction.RESEND:
        for n in existing:
            if n.status != NotificationStatus.RESOLVED:
                n.status = NotificationStatus.RESOLVED
        db.add(
            Notification(
                alert_config_id=alert.id,
                vulnerability_id=vuln_id,
                service_ids=current_services,
                channel=channel,
                status=NotificationStatus.SENT if success else NotificationStatus.FAILED,
                attempts=0 if success else 1,
            )
        )
        return

    failed = [n for n in existing if n.status == NotificationStatus.FAILED]
    status = NotificationStatus.SENT if success else NotificationStatus.FAILED
    attempts = 0 if success else max((n.attempts for n in failed), default=0) + 1

    if failed:
        for n in failed:
            n.status = status
            n.channel = channel
            n.attempts = attempts
            n.service_ids = current_services
    else:
        db.add(
            Notification(
                alert_config_id=alert.id,
                vulnerability_id=vuln_id,
                service_ids=current_services,
                channel=channel,
                status=status,
                attempts=attempts,
            )
        )


async def _do_check_alerts(db: AsyncSession) -> None:
    vulns, open_pairs, services_by_vuln = await _open_vulnerabilities(db)
    alerts = await _enabled_alerts(db)
    if not alerts:
        return

    alert_by_id = {a.id: a for a in alerts}
    notifications = await _load_notifications(db, alert_by_id)
    _resolve_closed_episodes(notifications, alert_by_id, open_pairs)
    by_pair = _index_by_pair(notifications)

    for alert in alerts:
        for project_id, vuln_id in open_pairs:
            if project_id != alert.project_id:
                continue
            vuln = vulns[vuln_id]
            if _severity_rank(vuln.severity) > _severity_rank(alert.severity_threshold):
                continue

            existing = by_pair.get((vuln_id, alert.id), [])
            current_services = services_by_vuln.get(vuln_id, {}).get(project_id, [])
            action = _delivery_action(existing, current_services)
            if action in (_DeliveryAction.SKIP, _DeliveryAction.GIVE_UP):
                continue

            channel, success = await _deliver(alert, vuln)
            _record_delivery(
                db, alert, vuln_id, existing, action, channel, success, current_services
            )

    await db.commit()


@celery_app.task(name="tasks.snapshot_metrics")
def snapshot_metrics(snapshot_date: str | None = None):
    async def _run():
        async with _make_session()() as db:
            await _do_snapshot_metrics(db, snapshot_date)

    asyncio.run(_run())


async def _do_snapshot_metrics(db: AsyncSession, snapshot_date: str | None = None) -> None:
    target_date = date.fromisoformat(snapshot_date) if snapshot_date else date.today()

    result = await db.execute(select(Project.id))
    project_ids = result.scalars().all()

    for pid in project_ids:
        if target_date == date.today():
            open_vulns = await db.execute(
                select(Vulnerability.severity)
                .join(SBOMVulnerability)
                .join(SBOM)
                .where(
                    SBOM.project_id == pid,
                    SBOMVulnerability.status == VulnerabilityStatus.OPEN,
                )
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
                    SBOMVulnerability.status == VulnerabilityStatus.FIXED,
                    SBOMVulnerability.fixed_at.isnot(None),
                    func.date(SBOMVulnerability.fixed_at) <= target_date,
                )
                .distinct()
            )
            fixed_ids = set(r[0] for r in fixed_before)
            severities = [sev for vid, sev in total_dict.items() if vid not in fixed_ids]

        critical_count = sum(
            1 for s in severities if s == VulnerabilitySeverity.CRITICAL.value.lower()
        )
        high_count = sum(1 for s in severities if s == VulnerabilitySeverity.HIGH.value.lower())
        medium_count = sum(1 for s in severities if s == VulnerabilitySeverity.MEDIUM.value.lower())
        low_count = sum(1 for s in severities if s == VulnerabilitySeverity.LOW.value.lower())

        fixed_result = await db.execute(
            select(func.count(SBOMVulnerability.vulnerability_id))
            .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
            .where(
                SBOM.project_id == pid,
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
