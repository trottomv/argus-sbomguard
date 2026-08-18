"""OpenTelemetry tracing setup.

The application never hosts the ``/metrics`` endpoint itself: that is served
by the OTel Collector, which scrapes ``hostmetrics`` from the host filesystem
(mounted at ``/hostfs``) and exposes them on ``GET /metrics``. This module only
configures the application-side OpenTelemetry SDK so that *traces* can be
pushed to the Collector over OTLP/HTTP when enabled.

Export is gated by two settings: ``otel_traces_enabled`` and a non-empty
``otel_exporter_otlp_endpoint``. Both must be set for tracing to be active,
which keeps the codebase instrumentation-ready while staying silent by default.

When enabled, FastAPI request handling, outbound ``httpx`` calls (e.g. Slack
notifications) and Celery task execution are automatically instrumented, so
every HTTP request and every background task produces a distributed trace that
can be visualised in Jaeger.
"""

import logging

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.celery import CeleryInstrumentor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from config import settings

logger = logging.getLogger(__name__)


def init_tracing() -> None:
    """Configure the global trace provider.

    A no-op when tracing is disabled (``otel_traces_enabled`` is false or
    ``otel_exporter_otlp_endpoint`` is empty). Idempotent: calling it more than
    once does not replace an already-configured provider.
    """
    if not settings.otel_traces_enabled or not settings.otel_exporter_otlp_endpoint:
        logger.debug("OpenTelemetry tracing disabled")
        return

    provider = trace.get_tracer_provider()
    if isinstance(provider, TracerProvider):
        logger.debug("OpenTelemetry tracing already initialized, skipping")
        return

    resource = Resource.create({"service.name": settings.otel_service_name})
    exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    logger.info(
        "OpenTelemetry tracing enabled (service=%s, endpoint=%s)",
        settings.otel_service_name,
        settings.otel_exporter_otlp_endpoint,
    )


def instrument_fastapi(app) -> None:
    """Attach OpenTelemetry instrumentation to a FastAPI application.

    Only instruments when tracing is enabled; otherwise a no-op. Safe to call
    multiple times (the instrumentation library guards against double
    instrumentation).
    """
    if not settings.otel_traces_enabled or not settings.otel_exporter_otlp_endpoint:
        logger.debug("OpenTelemetry FastAPI instrumentation skipped (tracing disabled)")
        return
    FastAPIInstrumentor.instrument_app(app)
    logger.info("OpenTelemetry FastAPI instrumentation attached")


def instrument_httpx() -> None:
    """Instrument the ``httpx`` client for outbound request tracing.

    No-op when tracing is disabled.
    """
    if not settings.otel_traces_enabled or not settings.otel_exporter_otlp_endpoint:
        logger.debug("OpenTelemetry httpx instrumentation skipped (tracing disabled)")
        return
    HTTPXClientInstrumentor().instrument()
    logger.info("OpenTelemetry httpx instrumentation attached")


def instrument_celery() -> None:
    """Instrument Celery task execution for tracing.

    Uses the official Celery instrumentation (signal hooks) so every task run
    produces a span: the ``task_prerun``/``task_postrun``/``task_failure``
    signals are traced, task failures are recorded on the span, and outbound
    calls made inside a task become children of the task span. No-op when
    tracing is disabled.
    """
    if not settings.otel_traces_enabled or not settings.otel_exporter_otlp_endpoint:
        logger.debug("OpenTelemetry celery instrumentation skipped (tracing disabled)")
        return
    CeleryInstrumentor().instrument()
    logger.info("OpenTelemetry celery instrumentation attached")


def shutdown_tracing() -> None:
    """Shut down the trace provider, flushing any pending spans.

    Safe to call even when tracing was never enabled.
    """
    provider = trace.get_tracer_provider()
    if isinstance(provider, TracerProvider):
        provider.shutdown()


def get_tracer() -> trace.Tracer:
    """Return the tracer for the configured service.

    Falls back to a no-op tracer (from the global provider) when tracing is
    disabled, so callers can always obtain a tracer safely.
    """
    return trace.get_tracer(settings.otel_service_name)
