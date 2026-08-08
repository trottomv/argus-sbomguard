import uuid
from enum import StrEnum

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import BaseModel


class SeverityThreshold(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def label(self) -> str:
        return _SEVERITY_THRESHOLD_LABELS[self]


class NotificationChannel(StrEnum):
    EMAIL = "email"
    SLACK = "slack"

    @property
    def label(self) -> str:
        return _NOTIFICATION_CHANNEL_LABELS[self]


_SEVERITY_THRESHOLD_LABELS = {
    SeverityThreshold.CRITICAL: "Critical only",
    SeverityThreshold.HIGH: "High and above",
    SeverityThreshold.MEDIUM: "Medium and above",
    SeverityThreshold.LOW: "All",
}

_NOTIFICATION_CHANNEL_LABELS = {
    NotificationChannel.EMAIL: "Email",
    NotificationChannel.SLACK: "Slack",
}


class AlertConfig(BaseModel):
    __tablename__ = "alert_configs"

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id"), nullable=False, index=True
    )
    severity_threshold: Mapped[str] = mapped_column(String(20), default="high")
    notification_type: Mapped[str] = mapped_column(String(50), default="email")
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
    channel: Mapped[str | None] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="sent")
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

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
    status: Mapped[str] = mapped_column(String(50), default="open")

    project = relationship("Project", back_populates="pull_requests")
