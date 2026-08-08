import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from config import settings
from models.alert import AlertConfig, Notification
from models.project import Project
from models.sbom import SBOM
from models.service import Service
from models.vulnerability import SBOMVulnerability, Vulnerability
from services.tasks import (
    MAX_ALERT_DELIVERY_ATTEMPTS,
    _do_check_alerts,
    _do_scan_sbom,
    _latest_sbom_ids,
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
            channel="slack",
            status="failed",
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
    assert notifications[0].status == "sent"


@pytest.mark.asyncio
async def test_check_alerts_does_not_resend_sent_notification(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel="slack",
            status="sent",
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
    assert notifications[0].status == "sent"


@pytest.mark.asyncio
async def test_check_alerts_keeps_failed_when_send_fails_again(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel="slack",
            status="failed",
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
    assert notifications[0].status == "failed"
    assert notifications[0].attempts == 1


@pytest.mark.asyncio
async def test_check_alerts_gives_up_after_max_attempts(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            channel="slack",
            status="failed",
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
    assert notifications[0].status == "failed"


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
    assert notifications[0].status == "sent"
    assert notifications[0].channel == "email"


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
    assert notifications[0].status == "failed"


@pytest.mark.asyncio
async def test_check_alerts_does_not_resend_same_episode(db_session):
    vuln, alert = await _make_open_vuln_with_alert(db_session)
    link = (await db_session.execute(select(SBOMVulnerability))).scalar_one()
    db_session.add(
        Notification(
            alert_config_id=alert.id,
            vulnerability_id=vuln.id,
            sbom_vulnerability_id=link.id,
            channel="slack",
            status="sent",
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
            sbom_vulnerability_id=link.id,
            episode_link_ids=[str(link.id)],
            channel="slack",
            status="sent",
        )
    )
    await db_session.commit()

    # Close the first episode and reopen the vulnerability with a new link.
    link.status = "fixed"
    link.fixed_at = datetime.now(UTC)
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

    original = settings.slack_webhook_url
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
    assert all(n.status == "sent" for n in notifications)


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
            sbom_vulnerability_id=link.id,
            episode_link_ids=[str(link.id)],
            channel="slack",
            status="failed",
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

    # Reopen: the new episode resets the budget, so it delivers again.
    link.status = "fixed"
    link.fixed_at = datetime.now(UTC)
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
    assert newest.status == "sent"
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
            sbom_vulnerability_id=link1.id,
            episode_link_ids=[str(link1.id), str(link2.id)],
            channel="slack",
            status="sent",
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
