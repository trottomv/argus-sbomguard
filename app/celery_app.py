from celery import Celery
from celery.signals import worker_process_shutdown, worker_shutdown

from config import settings
from services.otel import init_tracing, instrument_celery, instrument_httpx, shutdown_tracing

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

# The worker/beat processes never import main.py, so initialize tracing here
# (idempotent: a no-op in the FastAPI process, which already initialized it).
# The web process also imports this module (via services.tasks): the celery
# instrumentation attached there is what injects the trace context into queued
# tasks, so the worker's task span links back to the originating HTTP request.
init_tracing()
instrument_celery()
instrument_httpx()


@worker_shutdown.connect
@worker_process_shutdown.connect
def _flush_traces_on_shutdown(*args, **kwargs) -> None:
    """Flush buffered spans when the worker (or a pool child) stops.

    Without this, the ``BatchSpanProcessor`` export interval (~5s) means the
    most recent task spans are lost on worker stop (deploys, restarts).
    ``shutdown_tracing`` is a no-op when tracing is disabled and safe to call
    on an already-shut-down provider.
    """
    shutdown_tracing()
