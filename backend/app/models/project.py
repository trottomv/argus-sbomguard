from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel


class Project(BaseModel):
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    repo_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(50), nullable=True)

    sboms = relationship("SBOM", back_populates="project", cascade="all, delete-orphan")
    alert_configs = relationship(
        "AlertConfig", back_populates="project", cascade="all, delete-orphan"
    )
    pull_requests = relationship(
        "PullRequest", back_populates="project", cascade="all, delete-orphan"
    )
