"""Structured (JSON) logging configuration built on the stdlib ``logging``.

Provides a ``setup_logging(level, log_format)`` helper that replaces the ad-hoc
``logging.basicConfig`` calls in ``main.py`` and ``entrypoint.py``. JSON output
is emitted via a small stdlib formatter (no extra dependency) so logs are easy
to ship to a log aggregator; ``text`` keeps the familiar human-readable format
for local development.

Also provides product-agnostic error tracking: ``log_exception`` emits an
unhandled exception as a structured ``event=exception`` JSON line carrying the
exception ``type``/``message``/``traceback``, the HTTP request context and, when
a recording OpenTelemetry span is active, its ``trace_id``/``span_id`` for
trace-log correlation. The event rides the same stdlib pipeline as every other
log line, so it can be routed to any log aggregator or error tracker without
vendor lock-in.
"""

from __future__ import annotations

import json
import logging
import traceback
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from opentelemetry import trace

if TYPE_CHECKING:
    from starlette.requests import Request

# Extra fields pulled from a log record by the JSON formatter when present.
# They are set via logging's ``extra`` argument, typically by ``log_exception``
# for structured error events.
_ERROR_EVENT_FIELDS = (
    "event",
    "type",
    "traceback",
    "trace_id",
    "span_id",
    "request_method",
    "request_path",
    "request_query",
    "request_client",
)


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "pid": record.process,
            "thread": record.threadName,
        }
        for field in _ERROR_EVENT_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def _route_uvicorn_to_root() -> None:
    """Reconfigure uvicorn's private loggers so they follow our output format.

    uvicorn installs its own ``uvicorn`` / ``uvicorn.access`` loggers with
    dedicated plain-text handlers and ``propagate=False``. Without this they
    would keep emitting text alongside our structured app logs, mixing formats
    in the same stream. Clearing their handlers and letting them propagate to
    the root logger keeps every line consistent (JSON by default).
    """
    for name in ("uvicorn", "uvicorn.error", "uvicorn.asgi", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True


def setup_logging(level: str = "info", log_format: str = "json") -> None:
    """Configure the root logger with the given level and output format."""
    if log_format == "text":
        formatter: logging.Formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"
        )
    else:
        formatter = JsonFormatter()

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    root.addHandler(handler)

    _route_uvicorn_to_root()


def log_exception(
    exc: BaseException,
    request: Request | None = None,
    logger: logging.Logger | None = None,
) -> None:
    """Log an unhandled exception as a structured ``event=exception`` line.

    The exception ``type``, ``message`` and full ``traceback`` are always
    included; when a ``request`` is given, the HTTP request context (method,
    path, query string, client address) is added too. When a recording
    OpenTelemetry span is active, its ``trace_id``/``span_id`` are attached so
    the event can be correlated with the distributed trace. The ``message``
    field is the exception text. Vendor-agnostic by design: the event is an
    ordinary structured log line, so it flows through ``LOG_FORMAT`` unchanged
    — with the ``text`` format the event-specific fields are simply not
    rendered.
    """
    log = logger or logging.getLogger("app")
    extra: dict[str, Any] = {
        "event": "exception",
        "type": type(exc).__name__,
        "traceback": "".join(traceback.format_exception(exc)),
    }
    span = trace.get_current_span()
    if span.is_recording():
        span_context = span.get_span_context()
        extra["trace_id"] = format(span_context.trace_id, "032x")
        extra["span_id"] = format(span_context.span_id, "016x")
    if request is not None:
        extra["request_method"] = request.method
        extra["request_path"] = request.url.path
        extra["request_query"] = request.url.query
        extra["request_client"] = request.client.host if request.client else None
    log.error(str(exc) or type(exc).__name__, extra=extra)
