"""qualify unaccent in public.slugify

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-19 08:20:00.000000

The slugify function references ``unaccent`` unqualified. pg_dump plain
restores run with an empty ``search_path`` and inline the SQL function, so
``unaccent`` does not resolve when the ``projects.slug`` generated column is
recreated — the restore fails with ``function unaccent(text) does not exist``.
Schema-qualify the reference so the function body resolves independently of the
search path (migration 0002 stays frozen; this recreates the function).

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.slugify(value text) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
        AS $slug$
            SELECT lower(regexp_replace(
                regexp_replace(public.unaccent(trim(value)), '[^[:alnum:]]+', '-', 'g'),
                '^-+|-+$', '', 'g'))
        $slug$
        """
    )


def downgrade() -> None:  # pragma: no cover - rollback path, never exercised by tests
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.slugify(value text) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
        AS $slug$
            SELECT lower(regexp_replace(
                regexp_replace(unaccent(trim(value)), '[^[:alnum:]]+', '-', 'g'),
                '^-+|-+$', '', 'g'))
        $slug$
        """
    )
