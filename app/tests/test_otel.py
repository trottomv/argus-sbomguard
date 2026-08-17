"""Tests for the OpenTelemetry tracing setup in services/otel.py."""

from unittest.mock import patch

import pytest
from opentelemetry.sdk.trace import TracerProvider

import services.otel as otel


@pytest.fixture(autouse=True)
def _isolate_otel_state(monkeypatch):
    """Reset settings and the global trace provider around each test."""
    monkeypatch.setattr(otel.settings, "otel_traces_enabled", False)
    monkeypatch.setattr(otel.settings, "otel_exporter_otlp_endpoint", "")
    monkeypatch.setattr(otel.settings, "otel_service_name", "argus-sbomguard")
    yield
    otel.trace.set_tracer_provider(TracerProvider())


def test_init_tracing_noop_when_disabled():
    with patch.object(otel, "OTLPSpanExporter") as exporter:
        otel.init_tracing()
        exporter.assert_not_called()


def test_init_tracing_noop_when_endpoint_empty(monkeypatch):
    monkeypatch.setattr(otel.settings, "otel_traces_enabled", True)
    with patch.object(otel, "OTLPSpanExporter") as exporter:
        otel.init_tracing()
        exporter.assert_not_called()


def test_init_tracing_enables_provider(monkeypatch):
    monkeypatch.setattr(otel.settings, "otel_traces_enabled", True)
    monkeypatch.setattr(
        otel.settings, "otel_exporter_otlp_endpoint", "http://otel-collector:4318/v1/traces"
    )

    with (
        patch.object(otel, "OTLPSpanExporter", return_value="exporter") as exporter_cls,
        patch.object(otel.trace, "set_tracer_provider") as set_provider,
        patch.object(otel, "BatchSpanProcessor") as processor_cls,
        patch.object(otel.trace, "get_tracer_provider", return_value=object()),
    ):
        otel.init_tracing()

        exporter_cls.assert_called_once_with(endpoint="http://otel-collector:4318/v1/traces")
        set_provider.assert_called_once()
        processor_cls.assert_called_once_with("exporter")
        provider = set_provider.call_args.args[0]
        assert isinstance(provider, TracerProvider)


def test_init_tracing_idempotent_skips_when_already_initialized(monkeypatch):
    monkeypatch.setattr(otel.settings, "otel_traces_enabled", True)
    monkeypatch.setattr(
        otel.settings, "otel_exporter_otlp_endpoint", "http://otel-collector:4318/v1/traces"
    )

    with (
        patch.object(otel, "OTLPSpanExporter") as exporter,
        patch.object(otel.trace, "set_tracer_provider") as set_provider,
        patch.object(otel.trace, "get_tracer_provider", return_value=TracerProvider()),
    ):
        otel.init_tracing()

        exporter.assert_not_called()
        set_provider.assert_not_called()


def test_shutdown_tracing_flushes_provider():
    provider = TracerProvider()
    with (
        patch.object(otel.trace, "get_tracer_provider", return_value=provider),
        patch.object(provider, "shutdown") as shutdown,
    ):
        otel.shutdown_tracing()
        shutdown.assert_called_once()


def test_shutdown_tracing_noop_when_not_provider():
    with patch.object(otel.trace, "get_tracer_provider", return_value=None):
        otel.shutdown_tracing()  # should not raise


def test_get_tracer_returns_tracer():
    tracer = otel.get_tracer()
    assert tracer is not None


def test_instrument_fastapi_noop_when_disabled():
    app = object()
    with patch.object(otel, "FastAPIInstrumentor") as instr:
        otel.instrument_fastapi(app)
        instr.instrument_app.assert_not_called()


def test_instrument_fastapi_attaches_when_enabled(monkeypatch):
    monkeypatch.setattr(otel.settings, "otel_traces_enabled", True)
    monkeypatch.setattr(
        otel.settings, "otel_exporter_otlp_endpoint", "http://otel-collector:4318/v1/traces"
    )
    app = object()
    with patch.object(otel, "FastAPIInstrumentor") as instr:
        otel.instrument_fastapi(app)
        instr.instrument_app.assert_called_once_with(app)


def test_instrument_httpx_noop_when_disabled():
    with patch.object(otel, "HTTPXClientInstrumentor") as instr:
        otel.instrument_httpx()
        instr.return_value.instrument.assert_not_called()


def test_instrument_httpx_attaches_when_enabled(monkeypatch):
    monkeypatch.setattr(otel.settings, "otel_traces_enabled", True)
    monkeypatch.setattr(
        otel.settings, "otel_exporter_otlp_endpoint", "http://otel-collector:4318/v1/traces"
    )
    with patch.object(otel, "HTTPXClientInstrumentor") as instr:
        otel.instrument_httpx()
        instr.return_value.instrument.assert_called_once_with()
