from sqlalchemy import Computed
from sqlalchemy.ext.compiler import compiles

# PostgreSQL expression for the generated slug column (the only supported
# runtime database). Non-alphanumeric runs are collapsed to a single hyphen,
# trimmed and lowercased: "Argus SBOM Guard" -> "argus-sbom-guard".
_SLUG_EXPR = (
    "lower(regexp_replace(regexp_replace(trim(name), '[^a-zA-Z0-9]+', '-', 'g'), "
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
        super().__init__(_SLUG_EXPR, **kw)
        self.sqlite_expr = sqlite_expr


@compiles(SlugComputed, "sqlite")
def _compile_slug_computed_sqlite(element: SlugComputed, compiler, **kw) -> str:
    return f"GENERATED ALWAYS AS ({element.sqlite_expr}) STORED"
