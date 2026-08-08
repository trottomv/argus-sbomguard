"""add missing base model columns

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-08

Models that did not inherit ``BaseModel`` were missing ``updated_at``
(and, for ``services``, ``created_at`` too). This migration backfills the
columns so the schema matches the ORM metadata.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _timestamp_column() -> sa.Column:
    return sa.Column(
        "updated_at",
        sa.DateTime(timezone=True),
        server_default=sa.text("now()"),
        nullable=False,
    )


def upgrade() -> None:
    for table in ("users", "login_tokens", "api_keys", "vulnerability_snapshots"):
        op.add_column(table, _timestamp_column())

    op.add_column(
        "services",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.add_column("services", _timestamp_column())

    # vulnerability_snapshots.created_at was created in 0001 without a server
    # default, but VulnerabilitySnapshot now inherits BaseModel whose created_at
    # declares server_default=now(). Align the DB column so autogenerate stops
    # emitting a spurious ALTER COLUMN SET DEFAULT.
    op.alter_column(
        "vulnerability_snapshots",
        "created_at",
        server_default=sa.text("now()"),
    )


def downgrade() -> None:
    op.drop_column("services", "updated_at")
    op.drop_column("services", "created_at")

    for table in ("users", "login_tokens", "api_keys", "vulnerability_snapshots"):
        op.drop_column(table, "updated_at")
