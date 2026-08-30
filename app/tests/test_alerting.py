import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from config import settings
from models.alert import (
    AlertConfig,
    Notification,
    NotificationChannel,
    NotificationStatus,
    SeverityThreshold,
)
from models.project import Project
from models.sbom import SBOM
from models.service import Service
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from services.alerting import (
    MAX_ALERT_DELIVERY_ATTEMPTS,
    _deliver,
    _delivery_action,
    _DeliveryAction,
    _discord_embed,
    _email_body,
    _package_names,
    _resolve_closed_episodes,
    _severity_color_hex,
    _severity_emoji,
    _slack_attachment,
    _truncate,
    do_check_alerts,
)


@pytest.mark.asyncio
async def test_check_alerts_no_enabled_alerts_skips(db_session):
    project = Project(name="no-alerts-project")
    db_session.add(project)
    await db_session.flush()

    sbom = SBOM(project_id=project.id, raw_sbom={}, sha256=uuid.uuid4().hex)
    db_session.add(sbom)
    await db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2026-0301", source="grype", severity=VulnerabilitySeverity.CRITICAL
    )
    db_session.add(vuln)
    await db_session.flush()
    db_session.add(
        SBOMVulnerability(
            sbom_id=sbom.id,
            dependency_purl="pkg:npm/x@1.0.0",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    with patch("services.alerting.send_slack", new_callable=AsyncMock) as mock_send:
        await do_check_alerts(db_session)
    mock_send.assert_not_called()


@pytest.mark.asyncio
async def test_check_alerts_skips_vulns_above_threshold(db_session):
    project = Project(name="threshold-project")
    db_session.add(project)
    await db_session.flush()

    sbom = SBOM(project_id=project.id, raw_sbom={}, sha256=uuid.uuid4().hex)
    db_session.add(sbom)
    await db_session.flush()

    low = Vulnerability(cve_id="CVE-2026-0302", source="grype", severity=VulnerabilitySeverity.LOW)
    db_session.add(low)
    await db_session.flush()
    db_session.add(
        SBOMVulnerability(
            sbom_id=sbom.id,
            dependency_purl="pkg:npm/low@1.0.0",
            vulnerability_id=low.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )

    alert = AlertConfig(
        project_id=project.id,
        severity_threshold=SeverityThreshold.HIGH,
        notification_type=NotificationChannel.SLACK,
        enabled=True,
    )
    db_session.add(alert)
    await db_session.commit()

    with patch("services.alerting.send_slack", new_callable=AsyncMock) as mock_send:
        await do_check_alerts(db_session)
    mock_send.assert_not_called()


@pytest.mark.asyncio
async def test_deliver_unsupported_channel(db_session):
    vuln = Vulnerability(
        cve_id="CVE-2026-0303", source="grype", severity=VulnerabilitySeverity.CRITICAL
    )
    db_session.add(vuln)
    await db_session.flush()

    alert = AlertConfig(
        project_id=uuid.uuid4(),
        severity_threshold=SeverityThreshold.HIGH,
        notification_type=NotificationChannel.SLACK,
        enabled=True,
    )
    alert.notification_type = "smoke-signals"

    channel, success = await _deliver(alert, vuln, project_name="Test Project", service_names=[])
    assert channel == "smoke-signals"
    assert success is False


async def _make_open_vuln_with_alert(
    db_session, notification_type: NotificationChannel = NotificationChannel.SLACK
):
    project = Project(name="alerts-project")
    db_session.add(project)
    await db_session.flush()

    sbom = SBOM(project_id=project.id, raw_sbom={}, sha256=uuid.uuid4().hex)
    db_session.add(sbom)
    await db_session.flush()

    vuln = Vulnerability(
        cve_id="CVE-2026-0101", source="grype", severity=VulnerabilitySeverity.CRITICAL
    )
    db_session.add(vuln)
    await db_session.flush()

    db_session.add(
        SBOMVulnerability(
            sbom_id=sbom.id,
            dependency_purl="pkg:npm/x@1.0.0",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )

    alert = AlertConfig(
        project_id=project.id,
        severity_threshold=SeverityThreshold.HIGH,
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
        with patch("services.alerting.send_slack", new_callable=AsyncMock, return_value=True):
            await do_check_alerts(db_session)
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
            channel=NotificationChannel.SLACK,
            status=NotificationStatus.SENT,
        )
    )
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
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
        with patch("services.alerting.send_slack", new_callable=AsyncMock, return_value=False):
            await do_check_alerts(db_session)
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
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 1
    assert notifications[0].status == NotificationStatus.FAILED


@pytest.mark.asyncio
async def test_check_alerts_delivers_email_to_env_recipients(db_session):
    _, _ = await _make_open_vuln_with_alert(db_session, notification_type=NotificationChannel.EMAIL)

    original = settings.alert_email_recipients
    settings.alert_email_recipients = ["ops@example.com"]
    try:
        with patch(
            "services.alerting.send_email", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
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
    _, _ = await _make_open_vuln_with_alert(db_session, notification_type=NotificationChannel.EMAIL)

    original = settings.alert_email_recipients
    settings.alert_email_recipients = []
    try:
        with patch(
            "services.alerting.send_email", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.alert_email_recipients = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 1
    assert notifications[0].status == NotificationStatus.FAILED


@pytest.mark.asyncio
async def test_check_alerts_delivers_discord_notification(db_session):
    _, _ = await _make_open_vuln_with_alert(
        db_session, notification_type=NotificationChannel.DISCORD
    )

    original = settings.discord_webhook_url
    settings.discord_webhook_url = "https://discord.com/api/webhooks/xxx/yyy"
    try:
        with patch(
            "services.alerting.send_discord", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
        mock_send.assert_awaited_once()
        assert mock_send.await_args.args[0] == "https://discord.com/api/webhooks/xxx/yyy"
    finally:
        settings.discord_webhook_url = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 1
    assert notifications[0].status == NotificationStatus.SENT
    assert notifications[0].channel == NotificationChannel.DISCORD


@pytest.mark.asyncio
async def test_check_alerts_discord_without_webhook_fails(db_session):
    _, _ = await _make_open_vuln_with_alert(
        db_session, notification_type=NotificationChannel.DISCORD
    )

    original = settings.discord_webhook_url
    settings.discord_webhook_url = ""
    try:
        with patch(
            "services.alerting.send_discord", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.discord_webhook_url = original

    notifications = (await db_session.execute(select(Notification))).scalars().all()
    assert len(notifications) == 1
    assert notifications[0].status == NotificationStatus.FAILED
    assert notifications[0].channel == NotificationChannel.DISCORD


def test_package_names_extracts_names():
    assert _package_names(None) == []
    assert _package_names([]) == []
    assert _package_names(["pkg:npm/"]) == []
    assert _package_names(
        [
            "pkg:deb/debian/gawk@1%3A5.2.1-2?arch=amd64",
            "pkg:npm/x@1.0.0",
            "pkg:npm/x@1.0.0",
        ]
    ) == ["gawk", "x"]


def test_email_body_basic():
    original = settings.domain
    settings.domain = ""
    try:
        body = _email_body(
            cve_id="CVE-2026-1",
            severity="CRITICAL",
            project_name="Acme",
            service_names=[],
            affected=[],
            summary=None,
        )
    finally:
        settings.domain = original
    assert body == "🔴 CVE-2026-1 (CRITICAL)\nProject: Acme\nServices: n/a"


def test_email_body_with_context_and_link():
    original = settings.domain
    settings.domain = "argus.example.com"
    try:
        body = _email_body(
            cve_id="CVE-2026-40468",
            severity="CRITICAL",
            project_name="Acme",
            service_names=["api", "billing"],
            affected=["gawk"],
            summary="Integer overflow",
        )
    finally:
        settings.domain = original

    assert "Project: Acme" in body
    assert "Services: api, billing" in body
    assert "Affected: gawk" in body
    assert "Integer overflow" in body
    assert "Details: https://argus.example.com/vulnerabilities?cve_id=CVE-2026-40468" in body


def test_severity_color_hex_mapping():
    assert _severity_color_hex("CRITICAL") == "#ED4245"
    assert _severity_color_hex("HIGH") == "#FAA61A"
    assert _severity_color_hex("MEDIUM") == "#FEE75C"
    assert _severity_color_hex("LOW") == "#57F287"
    assert _severity_color_hex("UNKNOWN") == "#99AAB5"
    assert _severity_color_hex(None) == "#99AAB5"
    assert _severity_color_hex("weird") == "#99AAB5"


def test_severity_emoji_mapping():
    assert _severity_emoji("CRITICAL") == "🔴"
    assert _severity_emoji("HIGH") == "🟠"
    assert _severity_emoji("MEDIUM") == "🟡"
    assert _severity_emoji("LOW") == "🟢"
    assert _severity_emoji("UNKNOWN") == "⚪"
    assert _severity_emoji(None) == "⚪"
    assert _severity_emoji("weird") == "⚪"


def test_truncate():
    assert _truncate("short", 10) == "short"
    assert _truncate("a" * 20, 10) == "a" * 9 + "…"
    assert len(_truncate("a" * 20, 10)) == 10


def test_discord_embed_full():
    original = settings.domain
    settings.domain = "argus.example.com"
    try:
        embed = _discord_embed(
            cve_id="CVE-2026-40468",
            severity="CRITICAL",
            project_name="Acme",
            service_names=["api", "billing"],
            affected=["gawk"],
            summary="Integer overflow",
        )
    finally:
        settings.domain = original

    assert embed["title"] == "🔴 CVE-2026-40468 (CRITICAL)"
    assert embed["color"] == 0xED4245
    assert embed["url"] == "https://argus.example.com/vulnerabilities?cve_id=CVE-2026-40468"
    assert embed["description"] == (
        "**Project** `Acme`\n**Services** `api, billing`\n**Affected** `gawk`\nInteger overflow"
    )
    assert "fields" not in embed


def test_discord_embed_minimal():
    original = settings.domain
    settings.domain = ""
    try:
        embed = _discord_embed(
            cve_id="CVE-2026-1",
            severity=None,
            project_name="Acme",
            service_names=[],
            affected=[],
            summary=None,
        )
    finally:
        settings.domain = original

    assert embed["color"] == 0x99AAB5
    assert embed["title"] == "⚪ CVE-2026-1 (None)"
    assert "url" not in embed
    assert "fields" not in embed
    assert embed["description"] == "**Project** `Acme`\n**Services** `n/a`"


def test_slack_attachment_full():
    original = settings.domain
    settings.domain = "argus.example.com"
    try:
        attachment = _slack_attachment(
            cve_id="CVE-2026-40468",
            severity="CRITICAL",
            project_name="Acme",
            service_names=["api", "billing"],
            affected=["gawk"],
            summary="Integer overflow",
        )
    finally:
        settings.domain = original

    assert attachment["color"] == "#ED4245"
    assert attachment["title"] == "🔴 CVE-2026-40468 (CRITICAL)"
    assert attachment["fallback"] == "🔴 CVE-2026-40468 (CRITICAL)"
    assert (
        attachment["title_link"]
        == "https://argus.example.com/vulnerabilities?cve_id=CVE-2026-40468"
    )
    assert attachment["text"] == (
        "*Project* `Acme`\n*Services* `api, billing`\n*Affected* `gawk`\nInteger overflow"
    )
    assert "fields" not in attachment


def test_slack_attachment_minimal():
    original = settings.domain
    settings.domain = ""
    try:
        attachment = _slack_attachment(
            cve_id="CVE-2026-1",
            severity=None,
            project_name="Acme",
            service_names=[],
            affected=[],
            summary=None,
        )
    finally:
        settings.domain = original

    assert attachment["color"] == "#99AAB5"
    assert attachment["title"] == "⚪ CVE-2026-1 (None)"
    assert attachment["fallback"] == "⚪ CVE-2026-1 (None)"
    assert "title_link" not in attachment
    assert "fields" not in attachment
    assert attachment["text"] == "*Project* `Acme`\n*Services* `n/a`"


@pytest.mark.asyncio
async def test_check_alerts_delivers_email_with_context(db_session):
    _, _ = await _make_open_vuln_with_alert(db_session, notification_type=NotificationChannel.EMAIL)

    original_recipients = settings.alert_email_recipients
    original_url = settings.domain
    settings.alert_email_recipients = ["ops@example.com"]
    settings.domain = "argus.example.com"
    try:
        with patch(
            "services.alerting.send_email", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
        message = mock_send.await_args.args[2]
    finally:
        settings.alert_email_recipients = original_recipients
        settings.domain = original_url

    assert "Project: alerts-project" in message
    assert "Details: https://argus.example.com/vulnerabilities?cve_id=CVE-2026-0101" in message


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
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
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
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    # Close the episode: the notification becomes resolved.
    link.status = VulnerabilityStatus.FIXED
    link.fixed_at = datetime.now(UTC)
    await db_session.commit()

    try:
        with patch(
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    # Reopen with a new link: a fresh episode re-alerts.
    db_session.add(
        SBOMVulnerability(
            sbom_id=link.sbom_id,
            dependency_purl="pkg:npm/y@1.0.0",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
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
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
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
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    # Close the episode: the exhausted failed row is resolved.
    link.status = VulnerabilityStatus.FIXED
    link.fixed_at = datetime.now(UTC)
    await db_session.commit()

    try:
        with patch(
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    # Reopen: the new episode resets the budget, so it delivers again.
    db_session.add(
        SBOMVulnerability(
            sbom_id=link.sbom_id,
            dependency_purl="pkg:npm/y@1.0.0",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send2:
            await do_check_alerts(db_session)
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
        status=VulnerabilityStatus.OPEN,
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
    link1.status = VulnerabilityStatus.FIXED
    link1.fixed_at = datetime.now(UTC)
    await db_session.commit()

    original = settings.slack_webhook_url
    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
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

    vuln = Vulnerability(
        cve_id="CVE-2026-0202", source="grype", severity=VulnerabilitySeverity.CRITICAL
    )
    db_session.add(vuln)
    await db_session.flush()
    link1 = SBOMVulnerability(
        sbom_id=sbom1.id,
        dependency_purl="pkg:npm/x@1.0.0",
        vulnerability_id=vuln.id,
        status=VulnerabilityStatus.OPEN,
        detected_at=datetime.now(UTC),
    )
    link2 = SBOMVulnerability(
        sbom_id=sbom2.id,
        dependency_purl="pkg:npm/x@1.0.0",
        vulnerability_id=vuln.id,
        status=VulnerabilityStatus.OPEN,
        detected_at=datetime.now(UTC),
    )
    db_session.add_all([link1, link2])
    await db_session.flush()

    alert = AlertConfig(
        project_id=project.id,
        severity_threshold=SeverityThreshold.HIGH,
        notification_type=NotificationChannel.SLACK,
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
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
        mock_send.assert_not_called()
    finally:
        settings.slack_webhook_url = original

    # service-a is fixed but the vulnerability stays open in service-b: the
    # affected services changed, so the notification is re-sent for service-b.
    link1.status = VulnerabilityStatus.FIXED
    link1.fixed_at = datetime.now(UTC)
    await db_session.commit()

    settings.slack_webhook_url = _slack_webhook()
    try:
        with patch(
            "services.alerting.send_slack", new_callable=AsyncMock, return_value=True
        ) as mock_send:
            await do_check_alerts(db_session)
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
