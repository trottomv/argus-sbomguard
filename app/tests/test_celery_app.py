"""Regression tests for the Celery app configuration."""

from unittest.mock import patch

from celery_app import celery_app
from config import settings


def test_check_alerts_is_scheduled_in_beat():
    """tasks.check_alerts must be registered in the beat schedule.

    Regression guard: the task existed for a long time without being
    scheduled, so it never actually ran despite being documented as
    periodic.
    """
    entry = celery_app.conf.beat_schedule["check-alerts"]
    assert entry["task"] == "tasks.check_alerts"
    assert entry["schedule"] == settings.alerts_check_interval_seconds


def test_celery_app_import_initializes_tracing():
    """The worker/beat never import main.py, so celery_app must bootstrap OTel.

    This is what lets the Celery worker trace task execution and outbound
    httpx calls (e.g. Slack notifications) that originate in tasks.
    """
    import importlib

    import services.otel

    with (
        patch.object(services.otel, "init_tracing") as init,
        patch.object(services.otel, "instrument_celery") as instrument_celery,
        patch.object(services.otel, "instrument_httpx") as instrument_httpx,
    ):
        importlib.reload(importlib.import_module("celery_app"))
        init.assert_called_once()
        instrument_celery.assert_called_once()
        instrument_httpx.assert_called_once()


def test_worker_shutdown_flushes_traces():
    """The worker must flush buffered spans on shutdown so recent task traces
    survive deploys/restarts."""
    import celery_app

    with patch.object(celery_app, "shutdown_tracing") as shutdown:
        celery_app._flush_traces_on_shutdown()
        shutdown.assert_called_once()
