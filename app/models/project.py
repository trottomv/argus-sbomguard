from sqlalchemy import Computed, String, Text
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.base import BaseModel

# PostgreSQL expression for the generated slug column (the only supported
# runtime database). Non-alphanumeric runs are collapsed to a single hyphen,
# trimmed and lowercased: "Argus SBOM Guard" -> "argus-sbom-guard".
SLUG_EXPR = (
    "lower(regexp_replace(regexp_replace(trim(name), '[^a-zA-Z0-9]+', '-', 'g'), "
    "'^-+|-+$', '', 'g'))"
)
# SQLite-compatible fallback, used only by the unit-test fixture (SQLite has no
# regexp_replace). Same result for typical names; no runtime code depends on it.
SQLITE_SLUG_EXPR = (
    "lower(trim(replace(replace(replace(trim(name), ' ', '-'), '_', '-'), '.', '-'), '-'))"
)


class SlugComputed(Computed):
    """Generated column that stays PostgreSQL-only in production.

    A SQLite-specific compilation is registered for the unit-test fixture so
    ``Base.metadata.create_all`` still works there.
    """

    def __init__(self, sqlite_expr: str = SQLITE_SLUG_EXPR, **kw):
        super().__init__(SLUG_EXPR, **kw)
        self.sqlite_expr = sqlite_expr


@compiles(SlugComputed, "sqlite")
def _compile_slug_computed_sqlite(element: SlugComputed, compiler, **kw) -> str:
    return f"GENERATED ALWAYS AS ({element.sqlite_expr}) STORED"


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
