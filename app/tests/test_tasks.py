import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from services.tasks import (
    _make_session,
    check_alerts,
    rescan_vulnerabilities,
    scan_sbom,
    snapshot_metrics,
)


def test_make_session_builds_factory():
    factory = _make_session()
    assert factory is not None


def _mock_session_factory(monkeypatch):
    mock_session = AsyncMock()
    mock_factory = MagicMock(return_value=mock_session)
    monkeypatch.setattr("services.tasks._make_session", lambda: mock_factory)
    return mock_session


def test_scan_sbom_task_runs(monkeypatch):
    _mock_session_factory(monkeypatch)
    with patch("services.tasks._do_scan_sbom", new=AsyncMock()) as mock_do:
        scan_sbom(str(uuid.uuid4()))
        mock_do.assert_awaited_once()


def test_check_alerts_task_runs(monkeypatch):
    _mock_session_factory(monkeypatch)
    with patch("services.tasks._do_check_alerts", new=AsyncMock()) as mock_do:
        check_alerts()
        mock_do.assert_awaited_once()


def test_snapshot_metrics_task_runs(monkeypatch):
    _mock_session_factory(monkeypatch)
    with patch("services.tasks._do_snapshot_metrics", new=AsyncMock()) as mock_do:
        snapshot_metrics()
        mock_do.assert_awaited_once()


def test_rescan_vulnerabilities_task_runs(monkeypatch):
    _mock_session_factory(monkeypatch)
    fake_ids = [uuid.uuid4()]

    with (
        patch("services.tasks._latest_sbom_ids", new=AsyncMock(return_value=fake_ids)),
        patch("services.tasks.scan_sbom.delay") as mock_delay,
    ):
        rescan_vulnerabilities()
        mock_delay.assert_called_once_with(str(fake_ids[0]))
