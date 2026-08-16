"""Structured (JSON) logging configuration built on the stdlib ``logging``.

Provides a ``setup_logging(level, log_format)`` helper that replaces the ad-hoc
``logging.basicConfig`` calls in ``main.py`` and ``entrypoint.py``. JSON output
is emitted via a small stdlib formatter (no extra dependency) so logs are easy
to ship to a log aggregator; ``text`` keeps the familiar human-readable format
for local development.
"""

import json
import logging
from datetime import UTC, datetime
from typing import Any


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
