from celery import Celery

from config import settings

celery_app = Celery(
    "argus",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "snapshot-metrics-daily": {
            "task": "tasks.snapshot_metrics",
            "schedule": 60 * 60,  # every 1 hour
        },
        "rescan-vulnerabilities": {
            "task": "tasks.rescan_vulnerabilities",
            "schedule": settings.vuln_rescan_interval_seconds,  # every 12h by default
        },
        "check-alerts": {
            "task": "tasks.check_alerts",
            "schedule": settings.alerts_check_interval_seconds,  # every 1h by default
        },
    },
)

celery_app.autodiscover_tasks(["services"])
