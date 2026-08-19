import uuid
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models.alert import AlertConfig, Notification, NotificationChannel, NotificationStatus
from models.sbom import SBOM
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilityStatus,
)
from services.notifications import send_email, send_slack

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
    return {vuln.id: vuln for vuln in vulns.scalars().all()}, open_pairs, services_map


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
    active = [
        notification
        for notification in existing
        if notification.status != NotificationStatus.RESOLVED
    ]
    sent = [
        notification for notification in active if notification.status == NotificationStatus.SENT
    ]
    if sent:
        if set(sent[-1].service_ids or []) == set(current_services):
            return _DeliveryAction.SKIP
        return _DeliveryAction.RESEND

    failed = [
        notification
        for notification in existing
        if notification.status == NotificationStatus.FAILED
    ]
    if failed:
        if set(failed[-1].service_ids or []) != set(current_services):
            return _DeliveryAction.RESEND
        if max(notification.attempts for notification in failed) >= MAX_ALERT_DELIVERY_ATTEMPTS:
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
    for notification in notifications:
        alert = alert_by_id.get(notification.alert_config_id)
        if (
            alert is not None
            and (alert.project_id, notification.vulnerability_id) not in open_pairs
        ):
            notification.status = NotificationStatus.RESOLVED


def _index_by_pair(
    notifications: list[Notification],
) -> dict[tuple[uuid.UUID, uuid.UUID], list[Notification]]:
    by_pair: dict[tuple[uuid.UUID, uuid.UUID], list[Notification]] = {}
    for notification in notifications:
        by_pair.setdefault(
            (notification.vulnerability_id, notification.alert_config_id), []
        ).append(notification)
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
        for notification in existing:
            if notification.status != NotificationStatus.RESOLVED:
                notification.status = NotificationStatus.RESOLVED
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

    failed = [
        notification
        for notification in existing
        if notification.status == NotificationStatus.FAILED
    ]
    status = NotificationStatus.SENT if success else NotificationStatus.FAILED
    attempts = (
        0 if success else max((notification.attempts for notification in failed), default=0) + 1
    )

    if failed:
        for notification in failed:
            notification.status = status
            notification.channel = channel
            notification.attempts = attempts
            notification.service_ids = current_services
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


async def do_check_alerts(db: AsyncSession) -> None:
    vulns, open_pairs, services_by_vuln = await _open_vulnerabilities(db)
    alerts = await _enabled_alerts(db)
    if not alerts:
        return

    alert_by_id = {alert.id: alert for alert in alerts}
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
