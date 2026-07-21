import uuid

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel


class SBOM(BaseModel):
    __tablename__ = "sboms"

    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False, index=True
    )
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    format: Mapped[str | None] = mapped_column(String(50), nullable=True)
    raw_sbom: Mapped[dict] = mapped_column(JSONB, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    dependency_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    project = relationship("Project", back_populates="sboms")
    dependencies = relationship("Dependency", back_populates="sbom", cascade="all, delete-orphan")
    sbom_vulnerabilities = relationship("SBOMVulnerability", back_populates="sbom", cascade="all, delete-orphan")


class Dependency(BaseModel):
    __tablename__ = "dependencies"

    sbom_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sboms.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    purl: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    dep_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    license: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_direct: Mapped[bool] = mapped_column(default=False)
    metadata: Mapped[dict | None] = mapped_column(JSONB, default=dict)

    sbom = relationship("SBOM", back_populates="dependencies")
