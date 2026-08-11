from pathlib import Path

from pydantic import computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings

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
    log_level: str = "info"
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

    # Email recipients for alerts; comma-separated (or a JSON list) env value.
    alert_email_recipients: list[str] = []

    @field_validator("alert_email_recipients", mode="before")
    @classmethod
    def _split_email_recipients(cls, v: object) -> object:
        if isinstance(v, str):
            return [email.strip() for email in v.split(",") if email.strip()]
        return v

    # Vulnerabilities
    vuln_rescan_interval_seconds: int = 43200  # every 12 hours
    alerts_check_interval_seconds: int = 3600  # every 1 hour

    # gRPC
    grpc_port: int = 50051

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
