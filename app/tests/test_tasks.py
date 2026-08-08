import uuid
from datetime import UTC, date, datetime
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from config import settings
from models.alert import AlertConfig, Notification, NotificationChannel, NotificationStatus
from models.project import Project
from models.sbom import SBOM
from models.service import Service
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)
from services.tasks import (
    MAX_ALERT_DELIVERY_ATTEMPTS,
    _delivery_action,
    _DeliveryAction,
    _do_check_alerts,
    _do_scan_sbom,
    _do_snapshot_metrics,
    _latest_sbom_ids,
    _resolve_closed_episodes,
)


@pytest.mark.asyncio
async def test_latest_sbom_ids_picks_latest_per_scope(db_session):
    p1 = uuid.uuid4()
    p2 = uuid.uuid4()
    s1 = uuid.uuid4()
    s2 = uuid.uuid4()

    db_session.add_all(
        [Project(id=p1, name="Tasks project 1"), Project(id=p2, name="Tasks project 2")]
    )
    db_session.add_all(
        [
            Service(id=s1, project_id=p1, name="Tasks service 1"),
            Service(id=s2, project_id=p1, name="Tasks service 2"),
        ]
    )

    sboms = [
        SBOM(
            project_id=p1,
            service_id=s1,
            format="cyclonedx",
            raw_sbom={"v": "1"},
            sha256="a" * 64,
            uploaded_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        SBOM(
            project_id=p1,
            service_id=s1,
            format="cyclonedx",
            raw_sbom={"v": "2"},
            sha256="b" * 64,
            uploaded_at=datetime(2026, 1, 2, tzinfo=UTC),
        ),
        SBOM(
            project_id=p1,
            service_id=s2,
            format="cyclonedx",
            raw_sbom={"v": "1"},
            sha256="c" * 64,
            uploaded_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        SBOM(
            project_id=p1,
            format="cyclonedx",
            raw_sbom={"v": "1"},
            sha256="d" * 64,
            uploaded_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        SBOM(
            project_id=p2,
            format="cyclonedx",
            raw_sbom={"v": "1"},
            sha256="e" * 64,
            uploaded_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        SBOM(
            project_id=p2,
            format="cyclonedx",
            raw_sbom={"v": "2"},
            sha256="f" * 64,
            uploaded_at=datetime(2026, 1, 3, tzinfo=UTC),
        ),
    ]
    db_session.add_all(sboms)
    await db_session.commit()

    result = await _latest_sbom_ids(db_session)

    assert set(result) == {sboms[1].id, sboms[2].id, sboms[3].id, sboms[5].id}
    assert sboms[0].id not in result  # superseded by a newer SBOM for service s1
    assert sboms[4].id not in result  # superseded by a newer project-level SBOM for p2


async def _make_scope(db_session, project_id, older_uploaded, latest_uploaded):
    db_session.add(Project(id=project_id, name=f"Tasks project {project_id}"))
    older = SBOM(
        project_id=project_id,
        format="cyclonedx",
        raw_sbom={"v": "1"},
        sha256=uuid.uuid4().hex,
        uploaded_at=older_uploaded,
    )
    latest = SBOM(
        project_id=project_id,
        format="cyclonedx",
        raw_sbom={"v": "2"},
        sha256=uuid.uuid4().hex,
        uploaded_at=latest_uploaded,
    )
    db_session.add_all([older, latest])
    await db_session.flush()

    vuln = Vulnerability(cve_id="CVE-2026-0001", source="grype", severity="HIGH")
    db_session.add(vuln)
    await db_session.flush()

    link = SBOMVulnerability(
        sbom_id=older.id,
        dependency_purl="pkg:npm/example@1.0.0",
        vulnerability_id=vuln.id,
        status="open",
        detected_at=datetime.now(UTC),
    )
    db_session.add(link)
    await db_session.commit()
    return older, latest, vuln, link


@pytest.mark.asyncio
async def test_do_scan_sbom_skips_reconcile_when_scan_fails(db_session):
    project_id = uuid.uuid4()
    older, latest, _, _ = await _make_scope(
        db_session,
        project_id,
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 2, tzinfo=UTC),
    )

    with patch("services.tasks.scan_with_grype", new_callable=AsyncMock, return_value=None):
        await _do_scan_sbom(db_session, str(latest.id))

    fresh = (
        await db_session.execute(
            select(SBOMVulnerability).where(SBOMVulnerability.sbom_id == older.id)
        )
    ).scalar_one()
    assert fresh.status == "open"


@pytest.mark.asyncio
async def test_do_scan_sbom_reconciles_on_success(db_session):
    project_id = uuid.uuid4()
    older, latest, _, _ = await _make_scope(
        db_session,
        project_id,
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 2, tzinfo=UTC),
    )

    with patch("services.tasks.scan_with_grype", new_callable=AsyncMock, return_value=[]):
        await _do_scan_sbom(db_session, str(latest.id))

    fresh = (
        await db_session.execute(
            select(SBOMVulnerability).where(SBOMVulnerability.sbom_id == older.id)
        )
    ).scalar_one()
    assert fresh.status == "fixed"


@pytest.mark.asyncio
async def test_do_scan_sbom_retires_stale_vulns_on_latest(db_session):
    project_id = uuid.uuid4()
    _, latest, _, _ = await _make_scope(
        db_session,
        project_id,
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 2, tzinfo=UTC),
    )

    stale = Vulnerability(cve_id="CVE-2026-0009", source="grype", severity="LOW")
    db_session.add(stale)
    await db_session.flush()
    stale_link = SBOMVulnerability(
        sbom_id=latest.id,
        dependency_purl="pkg:npm/stale@2.0.0",
        vulnerability_id=stale.id,
        status="open",
        detected_at=datetime.now(UTC),
    )
    db_session.add(stale_link)
    await db_session.commit()

    with patch(
        "services.tasks.scan_with_grype",
        new_callable=AsyncMock,
        return_value=[{"id": "CVE-2026-9999"}],
    ):
        await _do_scan_sbom(db_session, str(latest.id))

    stale_fresh = (
        await db_session.execute(
            select(SBOMVulnerability).where(
                SBOMVulnerability.sbom_id == latest.id,
                SBOMVulnerability.dependency_purl == "pkg:npm/stale@2.0.0",
            )
        )
    ).scalar_one()
    assert stale_fresh.status == "fixed"


async def _make_open_vuln_with_alert(db_session, notification_type="slack"):
    project = Project(name="alerts-project")
    db_session.add(project)
    await db_session.flush()

    sbom = SBOM(project_id=project.id, raw_sbom={}, sha256=uuid.uuid4().hex)
    db_session.add(sbom)
    await db_session.flush()

    vuln = Vulnerability(cve_id="CVE-2026-0101", source="grype", severity="CRITICAL")
    db_session.add(vuln)
    await db_session.flush()

    db_session.add(
        SBOMVulnerability(
            sbom_id=sbom.id,
            dependency_purl="pkg:npm/x@1.0.0",
            vulnerability_id=vuln.id,
            status="open",
            detected_at=datetime.now(UTC),
        )
    )

    alert = AlertConfig(
        project_id=project.id,
        severity_threshold="high",
        notification_type=notification_type,
        enabled=True,
    )
    db_session.add(alert)
    await db_session.commit()
    return vuln, alert


def _slack_webhook() -> str:
    return "https://hooks.slack.com/services/xxx/yyy/zzz"


@pytest.mark.asyncio
async def test_check_alerts_retries_failed_notification(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel=NotificationChannel.SLACK,
            status=NotificationStatus.FAILED,
        )
    )
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch("services.tasks.send_slack", new_callable=AsyncMock, return_value=True):
            await _do_check_alerts(db_session)
    finally:
        settings.slack_webhook_url = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 1
    assert notifications[0].status == NotificationStatus.SENT


@pytest.mark.asyncio
async def test_check_alerts_does_not_resend_sent_notification(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel="slack",
            status=NotificationStatus.SENT,
        )
    )
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 1
    assert notifications[0].status == NotificationStatus.SENT


@pytest.mark.asyncio
async def test_check_alerts_keeps_failed_when_send_fails_again(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel=NotificationChannel.SLACK,
            status=NotificationStatus.FAILED,
        )
    )
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch("services.tasks.send_slack", new_callable=AsyncMock, return_value=False):
            await _do_check_alerts(db_session)
    finally:
        settings.slack_webhook_url = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 1
    assert notifications[0].status == NotificationStatus.FAILED
    assert notifications[0].attempts == 1


@pytest.mark.asyncio
async def test_check_alerts_gives_up_after_max_attempts(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel=NotificationChannel.SLACK,
            status=NotificationStatus.FAILED,
            attempts=MAX_ALERT_DELIVERY_ATTEMPTS,
        )
    )
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 1
    assert notifications[0].status == NotificationStatus.FAILED


@pytest.mark.asyncio
async def test_check_alerts_delivers_email_to_env_recipients(db_session):
    _, _ = await _make_open_vuln_with_alert(db_session, notification_type="email")

    original = settings.alert_email_recipients
    settings.alert_email_recipients = ["ops@example.com"]
    try:
        with patch(
            "services.tasks.send_email", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_awaited_once()
        assert mock_send.await_args.args[0] == "ops@example.com"
    finally:
        settings.alert_email_recipients = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 1
    assert notifications[0].status == NotificationStatus.SENT
    assert notifications[0].channel == NotificationChannel.EMAIL


@pytest.mark.asyncio
async def test_check_alerts_email_without_recipients_fails(db_session):
    _, _ = await _make_open_vuln_with_alert(db_session, notification_type="email")

    original = settings.alert_email_recipients
    settings.alert_email_recipients = []
    try:
        with patch(
            "services.tasks.send_email", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.alert_email_recipients = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 1
    assert notifications[0].status == NotificationStatus.FAILED


@pytest.mark.asyncio
async def test_check_alerts_does_not_resend_same_episode(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel=NotificationChannel.SLACK,
            status=NotificationStatus.SENT,
        )
    )
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original


@pytest.mark.asyncio
async def test_check_alerts_realerts_after_reopen(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    link = (await db_session.execute(select(SBOMVulnerability))).scalar_one()
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel=NotificationChannel.SLACK,
            status=NotificationStatus.SENT,
        )
    )
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    # Close the episode: the notification becomes resolved.
    link.status = "fixed"
    link.fixed_at = datetime.now(UTC)
    await db_session.commit()

    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    # Reopen with a new link: a fresh episode re-alerts.
    db_session.add(
        SBOMVulnerability(
            sbom_id=link.sbom_id,
            dependency_purl="pkg:npm/y@1.0.0",
            vulnerability_id=vuln.id,
            status="open",
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_awaited_once()
    finally:
        settings.slack_webhook_url = original

    # The previous episode's row is kept (history) and a new one is added.
    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 2
    assert {notification.status for notification in notifications} == {
        NotificationStatus.RESOLVED,
        NotificationStatus.SENT,
    }


@pytest.mark.asyncio
async def test_check_alerts_ignores_vulns_outside_alert_project(db_session):
    _, alert = await _make_open_vuln_with_alert(db_session)

    other_project = Project(name="other-project")
    db_session.add(other_project)
    await db_session.flush()
    alert.project_id = other_project.id
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original


@pytest.mark.asyncio
async def test_check_alerts_resets_attempts_on_new_episode(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    link = (await db_session.execute(select(SBOMVulnerability))).scalar_one()
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel=NotificationChannel.SLACK,
            status=NotificationStatus.FAILED,
            attempts=MAX_ALERT_DELIVERY_ATTEMPTS,
        )
    )
    await db_session.commit()

    # Same episode: the exhausted budget blocks the retry.
    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    # Close the episode: the exhausted failed row is resolved.
    link.status = "fixed"
    link.fixed_at = datetime.now(UTC)
    await db_session.commit()

    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    # Reopen: the new episode resets the budget, so it delivers again.
    db_session.add(
        SBOMVulnerability(
            sbom_id=link.sbom_id,
            dependency_purl="pkg:npm/y@1.0.0",
            vulnerability_id=vuln.id,
            status="open",
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send2:
            await _do_check_alerts(db_session)
        mock_send2.assert_awaited_once()
    finally:
        settings.slack_webhook_url = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 2
    newest = max(notifications, key=lambda n: n.created_at)
    assert newest.status == NotificationStatus.SENT
    assert newest.attempts == 0


@pytest.mark.asyncio
async def test_check_alerts_does_not_realert_while_episode_still_open(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    link1 = (await db_session.execute(select(SBOMVulnerability))).scalar_one()
    link2 = SBOMVulnerability(
        sbom_id=link1.sbom_id,
        dependency_purl="pkg:npm/y@1.0.0",
        vulnerability_id=vuln.id,
        status="open",
        detected_at=datetime.now(UTC),
    )
    db_session.add(link2)
    await db_session.flush()
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel=NotificationChannel.SLACK,
            status=NotificationStatus.SENT,
        )
    )
    await db_session.commit()

    # One link closes but the vulnerability stays open via the other: the
    # episode is still current, so no re-alert fires.
    link1.status = "fixed"
    link1.fixed_at = datetime.now(UTC)
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original


@pytest.mark.asyncio
async def test_check_alerts_resends_when_affected_services_change(db_session):
    project = Project(name="multi-service-project")
    db_session.add(project)
    await db_session.flush()
    s1 = Service(project_id=project.id, name="service-a")
    s2 = Service(project_id=project.id, name="service-b")
    db_session.add_all([s1, s2])
    await db_session.flush()

    sbom1 = SBOM(project_id=project.id, service_id=s1.id, raw_sbom={}, sha256=uuid.uuid4().hex)
    sbom2 = SBOM(project_id=project.id, service_id=s2.id, raw_sbom={}, sha256=uuid.uuid4().hex)
    db_session.add_all([sbom1, sbom2])
    await db_session.flush()

    vuln = Vulnerability(cve_id="CVE-2026-0202", source="grype", severity="CRITICAL")
    db_session.add(vuln)
    await db_session.flush()
    link1 = SBOMVulnerability(
        sbom_id=sbom1.id,
        dependency_purl="pkg:npm/x@1.0.0",
        vulnerability_id=vuln.id,
        status="open",
        detected_at=datetime.now(UTC),
    )
    link2 = SBOMVulnerability(
        sbom_id=sbom2.id,
        dependency_purl="pkg:npm/x@1.0.0",
        vulnerability_id=vuln.id,
        status="open",
        detected_at=datetime.now(UTC),
    )
    db_session.add_all([link1, link2])
    await db_session.flush()

    alert = AlertConfig(
        project_id=project.id,
        severity_threshold="high",
        notification_type="slack",
        enabled=True,
    )
    db_session.add(alert)
    await db_session.flush()
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            service_ids=sorted([str(s1.id), str(s2.id)]),
            channel=NotificationChannel.SLACK,
            status=NotificationStatus.SENT,
        )
    )
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    # service-a is fixed but the vulnerability stays open in service-b: the
    # affected services changed, so the notification is re-sent for service-b.
    link1.status = "fixed"
    link1.fixed_at = datetime.now(UTC)
    await db_session.commit()

    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.tasks.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await _do_check_alerts(db_session)
        mock_send.assert_awaited_once()
    finally:
        settings.slack_webhook_url = original

    notifications = (
        (await db_session.execute(select(Notification).order_by(Notification.created_at)))
        .scalars()
        .all()
    )
    assert len(notifications) == 2
    assert notifications[0].status == NotificationStatus.RESOLVED
    assert notifications[1].status == NotificationStatus.SENT
    assert notifications[1].service_ids == [str(s2.id)]


def _notification(
    *,
    status=NotificationStatus.SENT,
    attempts=0,
    service_ids=None,
    alert_config_id=None,
    vulnerability_id=None,
):
    return Notification(
        alert_config_id=alert_config_id or uuid.uuid4(),
        vulnerability_id=vulnerability_id or uuid.uuid4(),
        service_ids=service_ids,
        status=status,
        attempts=attempts,
    )


def test_delivery_action_skip_when_same_scope():
    existing = [_notification(status=NotificationStatus.SENT, service_ids=["a", "b"])]
    assert _delivery_action(existing, ["b", "a"]) is _DeliveryAction.SKIP


def test_delivery_action_resend_when_scope_changed():
    existing = [_notification(status=NotificationStatus.SENT, service_ids=["a", "b"])]
    assert _delivery_action(existing, ["b"]) is _DeliveryAction.RESEND


def test_delivery_action_retry_failed():
    existing = [_notification(status=NotificationStatus.FAILED, attempts=1)]
    assert _delivery_action(existing, []) is _DeliveryAction.RETRY


def test_delivery_action_give_up_after_max_attempts():
    existing = [
        _notification(status=NotificationStatus.FAILED, attempts=MAX_ALERT_DELIVERY_ATTEMPTS)
    ]
    assert _delivery_action(existing, []) is _DeliveryAction.GIVE_UP


def test_delivery_action_resend_when_scope_changed_even_if_exhausted():
    existing = [
        _notification(
            status=NotificationStatus.FAILED,
            attempts=MAX_ALERT_DELIVERY_ATTEMPTS,
            service_ids=["a", "b"],
        )
    ]
    assert _delivery_action(existing, ["b"]) is _DeliveryAction.RESEND


def test_delivery_action_deliver_first_time():
    assert _delivery_action([], []) is _DeliveryAction.DELIVER


def test_delivery_action_deliver_when_only_resolved_rows():
    existing = [_notification(status=NotificationStatus.RESOLVED)]
    assert _delivery_action(existing, []) is _DeliveryAction.DELIVER


def test_resolve_closed_episodes_marks_resolved_when_not_open():
    project_id = uuid.uuid4()
    alert = AlertConfig(id=uuid.uuid4(), project_id=project_id)
    n = _notification(alert_config_id=alert.id, vulnerability_id=uuid.uuid4())
    _resolve_closed_episodes([n], {alert.id: alert}, set())
    assert n.status == NotificationStatus.RESOLVED


def test_resolve_closed_episodes_keeps_open_pair():
    project_id = uuid.uuid4()
    vuln_id = uuid.uuid4()
    alert = AlertConfig(id=uuid.uuid4(), project_id=project_id)
    n = _notification(alert_config_id=alert.id, vulnerability_id=vuln_id)
    _resolve_closed_episodes([n], {alert.id: alert}, {(project_id, vuln_id)})
    assert n.status == NotificationStatus.SENT


@pytest.mark.asyncio
async def test_snapshot_metrics_counts_open_severities(db_session):
    project = Project(name="snapshot-test")
    db_session.add(project)
    await db_session.flush()

    sbom = SBOM(
        project_id=project.id,
        version="v1",
        format="cyclonedx",
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256="9" * 64,
    )
    db_session.add(sbom)
    await db_session.flush()

    vulns = [
        Vulnerability(
            cve_id="CVE-2026-9001", source="grype", severity=VulnerabilitySeverity.CRITICAL
        ),
        Vulnerability(cve_id="CVE-2026-9002", source="grype", severity=VulnerabilitySeverity.HIGH),
    ]
    db_session.add_all(vulns)
    await db_session.flush()

    for idx, vuln in enumerate(vulns):
        db_session.add(
            SBOMVulnerability(
                sbom_id=sbom.id,
                dependency_purl=f"pkg:npm/dep{idx}@1.0.0",
                vulnerability_id=vuln.id,
                status=VulnerabilityStatus.OPEN,
                detected_at=datetime.now(UTC),
            )
        )
    await db_session.commit()

    await _do_snapshot_metrics(db_session, date.today().isoformat())

    snap = (
        await db_session.execute(
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id == project.id)
        )
    ).scalar_one()
    assert snap.critical_count == 1
    assert snap.high_count == 1
    assert snap.medium_count == 0
    assert snap.low_count == 0
    assert snap.fixed_count == 0
