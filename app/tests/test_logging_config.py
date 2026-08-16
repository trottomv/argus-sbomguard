"""Tests for structured (JSON) logging configuration."""

import io
import json
import logging

import pytest
from pydantic import ValidationError

from config import Settings
from logging_config import JsonFormatter, setup_logging


@pytest.fixture(autouse=True)
def _restore_root_logger():
    root = logging.getLogger()
    before = (root.level, list(root.handlers))
    yield
    root.setLevel(before[0])
    root.handlers = before[1]


def _emit_record(logger: logging.Logger, message: str) -> str:
    logger.handlers = []
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


def test_json_formatter_includes_exc_info():
    logger = logging.getLogger("test.exc")
    logger.handlers = []
    stream = __import__("io").StringIO()
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


def test_log_format_setting_accepts_json_and_text():
    assert Settings(log_format="json", app_env="development").log_format == "json"
    assert Settings(log_format="text", app_env="development").log_format == "text"


def test_log_format_setting_rejects_unknown_values():
    with pytest.raises(ValidationError):
        Settings(log_format="xml", app_env="development")
