from sqlalchemy import Computed
from sqlalchemy.ext.compiler import compiles

# PostgreSQL slugify for the generated slug column (the only supported runtime
# database). The logic lives in the public.slugify(text) function created by
# migration 0002: it transliterates diacritics via the unaccent extension
# (wrapped as IMMUTABLE because unaccent itself is STABLE and generated columns
# require immutable expressions), keeps Unicode letters/digits (incl. CJK),
# collapses any other run to a single hyphen and lowercases: "Argus SBOM Guard"
# -> "argus-sbom-guard", "My Projéct" -> "my-project", "日本語" -> "日本語".
#
# Used by the SlugComputed column below. If you change the slugify rules,
# alembic revision --autogenerate will NOT detect it (PostgreSQL normalizes the
# stored generation_expression, so it never byte-matches the model SQL). You
# must hand-write a migration: CREATE OR REPLACE FUNCTION public.slugify, then
# recompute existing slugs (e.g. UPDATE projects SET name = name).
SLUG_EXPR = "public.slugify(name)"
# SQLite-compatible fallback, used only by the unit-test fixture (SQLite has no
# regexp_replace or unaccent). Same result for ASCII/CJK names; it diverges for
# accented names (diacritics are kept), so tests avoid asserting those.
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
