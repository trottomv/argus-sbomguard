from pydantic import computed_field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

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
    secret_key: str = "change-me-to-a-random-secret"
    app_env: str = "development"
    log_level: str = "info"

    # SMTP
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@argus.local"

    # Slack
    slack_webhook_url: str = ""

    # gRPC
    grpc_port: int = 50051

    # Auth
    admin_email: str = "admin@argus.local"
    login_token_expire_minutes: int = 15
    session_max_age_hours: int = 24


settings = Settings()
