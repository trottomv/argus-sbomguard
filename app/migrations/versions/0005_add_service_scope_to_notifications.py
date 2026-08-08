"""add service scope to notifications

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-08

Notifications are deduplicated per vulnerability episode (the period a
vulnerability stays open in a project): a fixed-then-reopened vulnerability
alerts again. The notification records the affected ``service_ids`` when it
was delivered, so the dedup can re-notify when the affected services change
while the vulnerability stays open.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("notifications", sa.Column("service_ids", sa.JSON(), nullable=True))


def downgrade() -> None:  # pragma: no cover - rollback path, never exercised by tests
    op.drop_column("notifications", "service_ids")
