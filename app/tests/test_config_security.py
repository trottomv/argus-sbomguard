"""Regression tests for session/secret configuration hardening."""

import pytest
from pydantic import ValidationError

from config import Settings

_PLACEHOLDER = "change-me-to-a-random-secret"


@pytest.fixture(autouse=True)
def _isolate_from_env(monkeypatch):
    # The test stack loads .env via env_file, so flags set for the dev app
    # (SHOW_LOGIN_CODE_IN_RESPONSE, OTEL_*) would otherwise leak into every
    # Settings() here and break these default/validity assertions. Drop them so
    # they are deterministic regardless of the developer's .env.
    for var in (
        "SHOW_LOGIN_CODE_IN_RESPONSE",
        "OTEL_TRACES_ENABLED",
        "OTEL_SERVICE_NAME",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_FORWARD_ENDPOINT",
    ):
        monkeypatch.delenv(var, raising=False)


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


def test_otel_settings_defaults():
    settings = Settings(app_env="development", secret_key=_PLACEHOLDER)
    assert settings.otel_traces_enabled is False
    assert settings.otel_service_name == "argus-sbomguard"
    assert settings.otel_exporter_otlp_endpoint == "http://otel-collector:4318/v1/traces"


def test_otel_settings_override():
    settings = Settings(
        app_env="development",
        secret_key=_PLACEHOLDER,
        otel_traces_enabled=True,
        otel_service_name="custom-service",
        otel_exporter_otlp_endpoint="http://otel-collector:4318/v1/traces",
    )
    assert settings.otel_traces_enabled is True
    assert settings.otel_service_name == "custom-service"
    assert settings.otel_exporter_otlp_endpoint == "http://otel-collector:4318/v1/traces"
