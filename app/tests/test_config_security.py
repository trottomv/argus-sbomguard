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


def test_show_login_code_defaults_to_false():
    assert (
        Settings(app_env="development", secret_key=_PLACEHOLDER).show_login_code_in_response
        is False
    )


def test_show_login_code_allowed_in_development_and_demo():
    assert (
        Settings(
            app_env="development",
            secret_key=_PLACEHOLDER,
            show_login_code_in_response=True,
        ).show_login_code_in_response
        is True
    )
    assert (
        Settings(
            app_env="demo",
            secret_key="a-strong-random-value",
            show_login_code_in_response=True,
        ).show_login_code_in_response
        is True
    )


def test_show_login_code_rejected_in_production():
    with pytest.raises(ValidationError):
        Settings(
            app_env="production",
            secret_key="a-strong-random-value",
            show_login_code_in_response=True,
        )


def test_alert_email_recipients_splits_comma_separated():
    settings = Settings(
        app_env="development",
        secret_key=_PLACEHOLDER,
        alert_email_recipients="ops@example.com, sec@example.com, ,",
    )
    assert settings.alert_email_recipients == ["ops@example.com", "sec@example.com"]


def test_alert_email_recipients_passthrough_list():
    settings = Settings(
        app_env="development",
        secret_key=_PLACEHOLDER,
        alert_email_recipients=["a@example.com"],
    )
    assert settings.alert_email_recipients == ["a@example.com"]


def test_invalid_display_timezone_rejected():
    with pytest.raises(ValidationError):
        Settings(app_env="development", secret_key=_PLACEHOLDER, display_timezone="Not/AZone")
