"""add attempts counter to notifications

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-08

Deliveries are retried when the previous send failed; the attempts counter
bounds how many retries happen before a permanently failing pair is given up.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "notifications",
        sa.Column("attempts", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("notifications", "attempts")
