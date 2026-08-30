"""widen notification channel columns to fit discord

Revision ID: 0009
Revises: 0008
Create Date: 2026-08-30 08:30:00.000000

The ``notification_channel`` columns are VARCHAR-backed (``native_enum=False``)
with a length derived from the longest enum value, so they were created as
``VARCHAR(5)`` when the only values were ``email``/``slack``. Adding ``discord``
(7 characters) makes the column overflow on insert. Widen both columns to the
new enum member set; no CHECK constraints exist, so this is a pure resize.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "alert_configs",
        "notification_type",
        existing_type=sa.Enum("email", "slack", name="notification_channel", native_enum=False),
        type_=sa.Enum("email", "slack", "discord", name="notification_channel", native_enum=False),
        existing_nullable=False,
    )
    op.alter_column(
        "notifications",
        "channel",
        existing_type=sa.Enum("email", "slack", name="notification_channel", native_enum=False),
        type_=sa.Enum("email", "slack", "discord", name="notification_channel", native_enum=False),
        existing_nullable=True,
    )


def downgrade() -> None:  # pragma: no cover - rollback path, never exercised by tests
    op.alter_column(
        "notifications",
        "channel",
        existing_type=sa.Enum(
            "email", "slack", "discord", name="notification_channel", native_enum=False
        ),
        type_=sa.Enum("email", "slack", name="notification_channel", native_enum=False),
        existing_nullable=True,
    )
    op.alter_column(
        "alert_configs",
        "notification_type",
        existing_type=sa.Enum(
            "email", "slack", "discord", name="notification_channel", native_enum=False
        ),
        type_=sa.Enum("email", "slack", name="notification_channel", native_enum=False),
        existing_nullable=False,
    )
