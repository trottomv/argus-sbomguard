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
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


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
