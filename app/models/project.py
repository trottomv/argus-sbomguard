from sqlalchemy import Computed, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import BaseModel

# PostgreSQL slugify for the generated slug column (the only supported runtime
# database). The logic lives in the public.slugify(text) function created by
# migration 0002: it transliterates diacritics via the unaccent extension
# (wrapped as IMMUTABLE because unaccent itself is STABLE and generated columns
# require immutable expressions), keeps Unicode letters/digits (incl. CJK),
# collapses any other run to a single hyphen and lowercases: "Argus SBOM Guard"
# -> "argus-sbom-guard", "My Projéct" -> "my-project", "日本語" -> "日本語".
#
# If you change the slugify rules, alembic revision --autogenerate will NOT
# detect it (PostgreSQL normalizes the stored generation_expression, so it never
# byte-matches the model SQL). You must hand-write a migration:
# CREATE OR REPLACE FUNCTION public.slugify, then recompute existing slugs
# (e.g. UPDATE projects SET name = name).
SLUG_EXPR = "public.slugify(name)"


class Project(BaseModel):
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(255), Computed(SLUG_EXPR), unique=True, index=True)
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
