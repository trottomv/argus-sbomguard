import uuid

from sqlalchemy import JSON, Boolean, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel


class AlertConfig(BaseModel):
    __tablename__ = "alert_configs"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False, index=True
    )
    severity_threshold: Mapped[str] = mapped_column(String(20), default="high")
    notification_type: Mapped[str] = mapped_column(String(50), default="slack")
    config: Mapped[dict | None] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    project = relationship("Project", back_populates="alert_configs")
    notifications = relationship(
        "Notification", back_populates="alert_config", cascade="all, delete-orphan"
    )


class Notification(BaseModel):
    __tablename__ = "notifications"

    alert_config_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alert_configs.id"), nullable=False
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=False
    )
    channel: Mapped[str | None] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="sent")

    alert_config = relationship("AlertConfig", back_populates="notifications")


class PullRequest(BaseModel):
    __tablename__ = "pull_requests"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False, index=True
    )
    dependency_name: Mapped[str] = mapped_column(String(512), nullable=False)
    from_version: Mapped[str] = mapped_column(String(255), nullable=False)
    to_version: Mapped[str] = mapped_column(String(255), nullable=False)
    pr_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="open")

    project = relationship("Project", back_populates="pull_requests")
