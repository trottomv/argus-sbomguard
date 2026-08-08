"""Regression tests for the Celery app configuration."""

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
