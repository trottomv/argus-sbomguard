"""Regression tests for session/secret configuration hardening."""

import pytest
from pydantic import ValidationError

from config import Settings

_PLACEHOLDER = "change-me-to-a-random-secret"


def test_placeholder_secret_key_rejected_outside_development():
    with pytest.raises(ValidationError):
        Settings(app_env="production", secret_key=_PLACEHOLDER)


def test_placeholder_secret_key_allowed_in_development():
    settings = Settings(app_env="development", secret_key=_PLACEHOLDER)
    assert settings.secret_key == _PLACEHOLDER


def test_strong_secret_key_accepted_in_production():
    settings = Settings(app_env="production", secret_key="a-strong-random-value")
    assert settings.secret_key == "a-strong-random-value"


def test_session_cookie_secure_follows_environment():
    assert Settings(app_env="development", secret_key=_PLACEHOLDER).session_cookie_secure is False
    assert (
        Settings(app_env="production", secret_key="a-strong-random-value").session_cookie_secure
        is True
    )
