"""Tests for structured (JSON) logging configuration."""

import io
import json
import logging

import pytest
from pydantic import ValidationError
from starlette.requests import Request

from config import Settings
from logging_config import JsonFormatter, log_exception, setup_logging


@pytest.fixture(autouse=True)
def _restore_root_logger():
    root = logging.getLogger()
    before = (root.level, list(root.handlers))
    yield
    root.setLevel(before[0])
    root.handlers = before[1]


def _emit_record(logger: logging.Logger, message: str) -> str:
    logger.handlers = []
    logger.propagate = False
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.error(message)
    logger.removeHandler(handler)
    return stream.getvalue().strip()


def test_json_formatter_emits_parseable_single_line():
    payload = json.loads(_emit_record(logging.getLogger("test.json"), "boom"))
    assert payload["level"] == "ERROR"
    assert payload["logger"] == "test.json"
    assert payload["message"] == "boom"
    assert payload["timestamp"]
    assert payload["module"] == "test_logging_config"
    assert payload["pid"] > 0
    assert payload["thread"]


def test_json_formatter_includes_exc_info():
    logger = logging.getLogger("test.exc")
    logger.handlers = []
    logger.propagate = False
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        raise ValueError("kaboom")
    except ValueError:
        logger.exception("failed")
    logger.removeHandler(handler)
    payload = json.loads(stream.getvalue().strip())
    assert "ValueError: kaboom" in payload["exc_info"]


def test_json_formatter_emits_error_event_extra_fields():
    logger = logging.getLogger("test.error_event")
    logger.handlers = []
    logger.propagate = False
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.error(
        "kaboom",
        extra={
            "event": "exception",
            "type": "RuntimeError",
            "traceback": "Traceback (most recent call last):\nRuntimeError: kaboom",
            "request_method": "GET",
            "request_path": "/boom",
            "request_query": "version=1",
            "request_client": "10.0.0.5",
        },
    )
    logger.removeHandler(handler)
    payload = json.loads(stream.getvalue().strip())
    assert payload["event"] == "exception"
    assert payload["type"] == "RuntimeError"
    assert payload["traceback"] == "Traceback (most recent call last):\nRuntimeError: kaboom"
    assert payload["request_method"] == "GET"
    assert payload["request_path"] == "/boom"
    assert payload["request_query"] == "version=1"
    assert payload["request_client"] == "10.0.0.5"
    assert payload["message"] == "kaboom"


def _capture_exception_event(exc: BaseException, request=None) -> dict:
    root = logging.getLogger()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        log_exception(exc, request=request)
    finally:
        root.removeHandler(handler)
    return json.loads(stream.getvalue().strip())


def test_log_exception_emits_structured_event_without_request():
    payload = _capture_exception_event(KeyError("missing"))
    assert payload["level"] == "ERROR"
    assert payload["logger"] == "app"
    assert payload["event"] == "exception"
    assert payload["type"] == "KeyError"
    assert payload["message"] == "'missing'"
    assert "KeyError: 'missing'" in payload["traceback"]
    assert not any(key.startswith("request_") for key in payload)
    assert "trace_id" not in payload
    assert "span_id" not in payload


def test_log_exception_includes_trace_context():
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.trace import TracerProvider

    previous_provider = otel_trace.get_tracer_provider()
    otel_trace.set_tracer_provider(TracerProvider())
    try:
        tracer = otel_trace.get_tracer("test")
        with tracer.start_as_current_span("boom"):
            payload = _capture_exception_event(RuntimeError("kaboom"))
    finally:
        otel_trace.set_tracer_provider(previous_provider)
    assert len(payload["trace_id"]) == 32
    assert len(payload["span_id"]) == 16
    assert payload["trace_id"] != "0" * 32
    assert payload["span_id"] != "0" * 16


def test_log_exception_includes_request_context():
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/upload",
        "query_string": b"version=1",
        "client": ("10.0.0.5", 54321),
        "headers": [],
        "scheme": "http",
        "server": ("test", 80),
    }
    payload = _capture_exception_event(ValueError("bad input"), request=Request(scope))
    assert payload["event"] == "exception"
    assert payload["type"] == "ValueError"
    assert payload["message"] == "bad input"
    assert "ValueError: bad input" in payload["traceback"]
    assert payload["request_method"] == "POST"
    assert payload["request_path"] == "/upload"
    assert payload["request_query"] == "version=1"
    assert payload["request_client"] == "10.0.0.5"


def test_log_exception_empty_message_falls_back_to_type_name():
    payload = _capture_exception_event(ValueError())
    assert payload["message"] == "ValueError"


def test_setup_logging_defaults_to_json():
    setup_logging()
    root = logging.getLogger()
    assert root.level == logging.INFO
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)


def test_setup_logging_text_format_uses_std_formatter():
    setup_logging("debug", "text")
    root = logging.getLogger()
    assert root.level == logging.DEBUG
    assert isinstance(root.handlers[0].formatter, logging.Formatter)
    assert not isinstance(root.handlers[0].formatter, JsonFormatter)


def test_setup_logging_unknown_level_falls_back_to_info():
    setup_logging("bogus-level", "json")
    assert logging.getLogger().level == logging.INFO


def test_setup_logging_replaces_existing_handlers():
    root = logging.getLogger()
    root.addHandler(logging.NullHandler())
    setup_logging("info", "json")
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)


def test_setup_logging_routes_uvicorn_loggers_to_root():
    setup_logging()
    for name in ("uvicorn", "uvicorn.error", "uvicorn.asgi", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        assert uvicorn_logger.propagate is True
        assert uvicorn_logger.handlers == []


def test_log_format_setting_accepts_json_and_text():
    assert Settings(log_format="json", app_env="development").log_format == "json"
    assert Settings(log_format="text", app_env="development").log_format == "text"


def test_log_format_setting_rejects_unknown_values():
    with pytest.raises(ValidationError):
        Settings(log_format="xml", app_env="development")
