from sqlalchemy import Computed
from sqlalchemy.ext.compiler import compiles

# PostgreSQL expression for the generated slug column (the only supported
# runtime database). Non-alphanumeric runs are collapsed to a single hyphen,
# trimmed and lowercased. The POSIX class [:alnum:] is Unicode-aware in a
# UTF-8 locale, so international names are preserved: "Argus SBOM Guard"
# -> "argus-sbom-guard", "Mio Progetto" -> "mio-progetto".
#
# Used by the SlugComputed column below. If you change this expression, alembic
# revision --autogenerate will NOT detect it (PostgreSQL normalizes the stored
# generation_expression — e.g. TRIM(BOTH FROM name), ::text casts — so it never
# byte-matches the model SQL). You must hand-write a migration instead, e.g.
# op.alter_column("projects", "slug", existing_type=sa.String(255),
# computed=sa.Computed(SLUG_EXPR), existing_nullable=False).
SLUG_EXPR = (
    "lower(regexp_replace(regexp_replace(trim(name), '[^[:alnum:]]+', '-', 'g'), "
    "'^-+|-+$', '', 'g'))"
)
# SQLite-compatible fallback, used only by the unit-test fixture (SQLite has no
# regexp_replace). Same result for typical names; no runtime code depends on it.
_SQLITE_SLUG_EXPR = (
    "lower(trim(replace(replace(replace(trim(name), ' ', '-'), '_', '-'), '.', '-'), '-'))"
)


class SlugComputed(Computed):
    """Generated column that stays PostgreSQL-only in production.

    A SQLite-specific compilation is registered for the unit-test fixture so
    ``Base.metadata.create_all`` still works there.
    """

    def __init__(self, sqlite_expr: str = _SQLITE_SLUG_EXPR, **kw):
        super().__init__(SLUG_EXPR, **kw)
        self.sqlite_expr = sqlite_expr


@compiles(SlugComputed, "sqlite")
def _compile_slug_computed_sqlite(element: SlugComputed, compiler, **kw) -> str:
    return f"GENERATED ALWAYS AS ({element.sqlite_expr}) STORED"
