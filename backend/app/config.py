from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://argus:argus@postgres:5432/argus"
    celery_broker_url: str = "amqp://argus:argus@rabbitmq:5672//"
    celery_result_backend: str = "rpc://"
    app_secret_key: str = "change-me-to-a-random-secret"
    app_env: str = "development"
    log_level: str = "info"

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@argus.local"

    slack_webhook_url: str = ""

    github_token: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
