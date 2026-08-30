import uuid

from sqlalchemy import JSON, Boolean, Enum, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import BaseModel, ValueLabelEnum, enum_db_values


class SeverityThreshold(ValueLabelEnum):
    CRITICAL = "critical", "Critical only"
    HIGH = "high", "High and above"
    MEDIUM = "medium", "Medium and above"
    LOW = "low", "All"


class NotificationChannel(ValueLabelEnum):
    EMAIL = "email", "Email"
    SLACK = "slack", "Slack"
    DISCORD = "discord", "Discord"


class NotificationStatus(ValueLabelEnum):
    SENT = "sent", "Sent"
    FAILED = "failed", "Failed"
    RESOLVED = "resolved", "Resolved"


class PullRequestStatus(ValueLabelEnum):
    OPEN = "open", "Open"


class AlertConfig(BaseModel):
    __tablename__ = "alert_configs"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id"), nullable=False, index=True
    )
    severity_threshold: Mapped[SeverityThreshold] = mapped_column(
        Enum(
            SeverityThreshold,
            name="severity_threshold",
            values_callable=enum_db_values,
            native_enum=False,
        ),
        default=SeverityThreshold.HIGH,
    )
    notification_type: Mapped[NotificationChannel] = mapped_column(
        Enum(
            NotificationChannel,
            name="notification_channel",
            values_callable=enum_db_values,
            native_enum=False,
        ),
        default=NotificationChannel.EMAIL,
    )
    config: Mapped[dict | None] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    project = relationship("Project", back_populates="alert_configs")
    notifications = relationship(
        "Notification", back_populates="alert_config", cascade="all, delete-orphan"
    )


class Notification(BaseModel):
    __tablename__ = "notifications"

    alert_config_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("alert_configs.id"), nullable=False
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=False
    )
    service_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    channel: Mapped[NotificationChannel | None] = mapped_column(
        Enum(
            NotificationChannel,
            name="notification_channel",
            values_callable=enum_db_values,
            native_enum=False,
        ),
        nullable=True,
    )
    status: Mapped[NotificationStatus] = mapped_column(
        Enum(
            NotificationStatus,
            name="notification_status",
            values_callable=enum_db_values,
            native_enum=False,
        ),
        default=NotificationStatus.SENT,
    )
    attempts: Mapped[int] = mapped_column(Integer, server_default="0", default=0, nullable=False)

    alert_config = relationship("AlertConfig", back_populates="notifications")


class PullRequest(BaseModel):
    __tablename__ = "pull_requests"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id"), nullable=False, index=True
    )
    dependency_name: Mapped[str] = mapped_column(String(512), nullable=False)
    from_version: Mapped[str] = mapped_column(String(255), nullable=False)
    to_version: Mapped[str] = mapped_column(String(255), nullable=False)
    pr_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[PullRequestStatus] = mapped_column(
        Enum(
            PullRequestStatus,
            name="pull_request_status",
            values_callable=enum_db_values,
            native_enum=False,
        ),
        default=PullRequestStatus.OPEN,
    )

    project = relationship("Project", back_populates="pull_requests")
