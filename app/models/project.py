from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import BaseModel
from models.columns import SlugComputed


class Project(BaseModel):
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(255), SlugComputed(), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    repo_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(50), nullable=True)

    sboms = relationship("SBOM", back_populates="project", cascade="all, delete-orphan")
    services = relationship("Service", back_populates="project", cascade="all, delete-orphan")
    alert_configs = relationship(
        "AlertConfig", back_populates="project", cascade="all, delete-orphan"
    )
    pull_requests = relationship(
        "PullRequest", back_populates="project", cascade="all, delete-orphan"
    )
