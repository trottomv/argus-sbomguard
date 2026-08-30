import os
from pathlib import Path
from typing import Annotated

from pydantic import Field, ValidationInfo, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode

_INSECURE_SECRET_KEY = "change-me-to-a-random-secret"  # nosec

_VERSION_FILE = Path(__file__).resolve().parent / "VERSION.md"


def _read_version_file(path: Path | None = None) -> str:
    version_path = path or _VERSION_FILE
    try:
        return version_path.read_text().strip()
    except OSError:
        return "0.0.0-dev"


class Settings(BaseSettings):
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "env_ignore_empty": True,
    }

    # Database
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_user: str = "argus"
    postgres_password: str = "argus"
    postgres_db: str = "argus"

    @computed_field
    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # RabbitMQ / Celery
    rabbitmq_host: str = "rabbitmq"
    rabbitmq_port: int = 5672
    rabbitmq_user: str = "argus"
    rabbitmq_password: str = "argus"
    rabbitmq_vhost: str = ""

    @computed_field
    @property
    def celery_broker_url(self) -> str:
        return (
            f"amqp://{self.rabbitmq_user}:{self.rabbitmq_password}"
            f"@{self.rabbitmq_host}:{self.rabbitmq_port}/{self.rabbitmq_vhost}"
        )

    celery_result_backend: str = "rpc://"

    # App
    secret_key: str = _INSECURE_SECRET_KEY
    # Valid values: development | demo | production. Also used as the Docker
    # image tag (argussbomguard:${APP_ENV}).
    app_env: str = "development"
    app_version: str = _read_version_file()
    # Build provenance (repository, commit, environment). CI bakes these into
    # the image via build args (BUILD_GIT_SHA / BUILD_DATE / BUILD_SOURCE_URL /
    # BUILD_ENV); they fall back to "unknown" outside a release build. The
    # deployment environment is reported separately via app_env.
    build_git_sha: str = "unknown"
    build_date: str = "unknown"
    build_source_url: str = "unknown"
    build_env: str = "unknown"
    log_level: str = "info"
    # Structured log output format: "json" (default) or "text".
    log_format: str = "json"

    @field_validator("log_format")
    @classmethod
    def _validate_log_format(cls, v: str) -> str:
        if v not in {"json", "text"}:
            raise ValueError(f"log_format must be 'json' or 'text', got {v!r}")
        return v

    # Surface the one-time login code directly in the login page response.
    # Only for dev/demo setups without SMTP; rejected when app_env is production.
    show_login_code_in_response: bool = False

    # SMTP
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@argus.local"

    # Slack
    slack_webhook_url: str = ""

    # Discord
    discord_webhook_url: str = ""

    # Public hostname (same ``DOMAIN`` used by Caddy for TLS). Used to build the
    # base URL for absolute links in alert notifications. Defaults to
    # ``localhost`` so local deployments get ``https://localhost`` links out of
    # the box (Caddy serves HTTPS even with a self-signed certificate).
    domain: str = "localhost"

    @computed_field
    @property
    def notification_base_url(self) -> str:
        """Absolute base URL used to build alert notification links."""
        return f"https://{self.domain}" if self.domain else ""

    # Email recipients for alerts; comma-separated (or a JSON list) env value.
    # NoDecode keeps the raw string for the before-validator: pydantic-settings
    # would otherwise try to json.loads() the env value (complex type) and crash
    # on a plain comma-separated list.
    alert_email_recipients: Annotated[list[str], NoDecode] = []

    @field_validator("alert_email_recipients", mode="before")
    @classmethod
    def _split_email_recipients(cls, v: object) -> object:
        if isinstance(v, str):
            return [email.strip() for email in v.split(",") if email.strip()]
        return v

    # Vulnerabilities
    vuln_rescan_interval_seconds: int = 43200  # every 12 hours
    alerts_check_interval_seconds: int = 3600  # every 1 hour
    # Daily vulnerability snapshots are retained for this many days; older rows
    # are pruned on each scheduled run (the dashboard chart shows this window).
    # Retention is always on: the chart renders this window (30-180 days).
    snapshot_retention_days: int = Field(default=30, ge=30, le=180)
    # SBOMs older than this many days are pruned, keeping at least the latest
    # SBOM per service/project as a safety net. Set to 0 (or an empty value in
    # the container environment) to keep SBOMs forever (retention disabled).
    # 0 is the portable choice: an empty value only disables when injected as a
    # real environment variable (e.g. via compose env_file), not when read from
    # a bare .env file by pydantic (env_ignore_empty filters it).
    sbom_retention_days: int | None = Field(default=365)

    @field_validator("sbom_retention_days", mode="before")
    @classmethod
    def _sbom_retention_days(cls, v: object, info: ValidationInfo) -> object:
        # env_ignore_empty filters empty env vars before this validator, so read
        # the raw env value to let an explicit empty string disable retention.
        raw = os.environ.get(info.field_name.upper())
        if raw == "":
            return None
        if v in (None, 0, "0", ""):
            return None
        try:
            value = int(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{info.field_name} must be an integer, got {v!r}") from exc
        if value < 1:
            raise ValueError(f"{info.field_name} must be >= 1 when set, got {value}")
        return value

    # gRPC
    grpc_port: int = 50051

    # Readiness
    readiness_timeout_seconds: float = 5.0

    # Observability (OpenTelemetry)
    # Enable pushing OpenTelemetry traces to the OTel Collector via OTLP/HTTP.
    # /metrics is always served by the OTel Collector (hostmetrics), so this only
    # controls application-level trace export. Defaults to off.
    otel_traces_enabled: bool = False
    # Service name reported in the OpenTelemetry resource.
    otel_service_name: str = "argus-sbomguard"
    # OTLP/HTTP endpoint the application pushes traces to. The app always talks
    # to the in-stack Collector, which is responsible for forwarding to the
    # final backend. The explicit /v1/traces path is required: the OTLP HTTP
    # exporter posts to the endpoint path verbatim. Traces are only exported
    # when otel_traces_enabled and this is set.
    otel_exporter_otlp_endpoint: str = "http://otel-collector:4318/v1/traces"

    # Display
    display_timezone: str = "UTC"

    @field_validator("display_timezone")
    @classmethod
    def validate_timezone(cls, v: str) -> str:
        from zoneinfo import available_timezones

        if v not in available_timezones():
            raise ValueError(f"Invalid timezone: {v}")
        return v

    # Auth
    admin_email: str = "admin@argus.local"
    login_token_expire_minutes: int = 15
    session_max_age_hours: int = 24

    @computed_field
    @property
    def session_cookie_secure(self) -> bool:
        """Mark the session cookie ``Secure`` outside local development."""
        return self.app_env != "development"

    @model_validator(mode="after")
    def _reject_insecure_secret_key(self) -> "Settings":
        if self.app_env != "development" and self.secret_key == _INSECURE_SECRET_KEY:
            raise ValueError(
                "secret_key must be set to a strong random value when app_env is "
                "not 'development' (generate one with "
                '`python -c "import secrets; print(secrets.token_urlsafe(48))"`)'
            )
        if self.app_env == "production" and self.show_login_code_in_response:
            raise ValueError(
                "show_login_code_in_response must be disabled when app_env is "
                "'production' (the one-time login code must never be surfaced "
                "to the response in production)"
            )
        return self


settings = Settings()
