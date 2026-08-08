"""convert string fields to enums

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-08 20:11:57.633993

Convert app-controlled string columns to enumerated types (VARCHAR backed by
``sqlalchemy.Enum`` with ``native_enum=False``) so the column types match the
Python ``ValueLabelEnum`` members used by the API schemas. No database-level
CHECK constraints are created: enforcement happens in the API schemas and the
ORM, and legacy values are normalized before the columns are altered.

Existing rows are normalized before the columns are altered: vulnerability
severities are uppercased and any out-of-set value mapped to ``UNKNOWN``; SBOM
formats and notification channels are lowercased and any remaining out-of-set
value reset to ``NULL``; notification, vulnerability and pull-request statuses
are lowercased and any remaining out-of-set value reset to the column's
default (``sent``/``open``). This guards against stray legacy values failing
the column resize or surfacing as read-time enum lookup errors.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Normalize legacy values before the columns are resized.
    op.execute(
        """
        UPDATE vulnerabilities
        SET severity = upper(severity)
        WHERE severity IS NOT NULL
        """
    )
    op.execute(
        """
        UPDATE vulnerabilities
        SET severity = 'UNKNOWN'
        WHERE severity IS NOT NULL
          AND severity NOT IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
        """
    )
    op.execute(
        """
        UPDATE sboms
        SET format = lower(format)
        WHERE format IS NOT NULL
        """
    )
    op.execute(
        """
        UPDATE sboms
        SET format = NULL
        WHERE format IS NOT NULL AND format NOT IN ('cyclonedx', 'spdx')
        """
    )
    op.execute(
        """
        UPDATE notifications
        SET channel = lower(channel)
        WHERE channel IS NOT NULL
        """
    )
    op.execute(
        """
        UPDATE notifications
        SET channel = NULL
        WHERE channel IS NOT NULL AND channel NOT IN ('email', 'slack')
        """
    )
    op.execute(
        """
        UPDATE notifications
        SET status = lower(status)
        WHERE status IS NOT NULL
        """
    )
    op.execute(
        """
        UPDATE notifications
        SET status = 'sent'
        WHERE status NOT IN ('sent', 'failed', 'resolved')
        """
    )
    op.execute(
        """
        UPDATE sbom_vulnerabilities
        SET status = lower(status)
        WHERE status IS NOT NULL
        """
    )
    op.execute(
        """
        UPDATE sbom_vulnerabilities
        SET status = 'open'
        WHERE status NOT IN ('open', 'fixed')
        """
    )
    op.execute(
        """
        UPDATE pull_requests
        SET status = lower(status)
        WHERE status IS NOT NULL
        """
    )
    op.execute(
        """
        UPDATE pull_requests
        SET status = 'open'
        WHERE status NOT IN ('open')
        """
    )

    op.alter_column(
        "alert_configs",
        "severity_threshold",
        existing_type=sa.VARCHAR(length=20),
        type_=sa.Enum(
            "critical", "high", "medium", "low", name="severity_threshold", native_enum=False
        ),
        existing_nullable=False,
    )
    op.alter_column(
        "alert_configs",
        "notification_type",
        existing_type=sa.VARCHAR(length=50),
        type_=sa.Enum("email", "slack", name="notification_channel", native_enum=False),
        existing_nullable=False,
    )
    op.alter_column(
        "notifications",
        "channel",
        existing_type=sa.VARCHAR(length=50),
        type_=sa.Enum("email", "slack", name="notification_channel", native_enum=False),
        existing_nullable=True,
    )
    op.alter_column(
        "notifications",
        "status",
        existing_type=sa.VARCHAR(length=50),
        type_=sa.Enum("sent", "failed", "resolved", name="notification_status", native_enum=False),
        existing_nullable=False,
    )
    op.alter_column(
        "pull_requests",
        "status",
        existing_type=sa.VARCHAR(length=50),
        type_=sa.Enum("open", name="pull_request_status", native_enum=False),
        existing_nullable=False,
    )
    op.alter_column(
        "sbom_vulnerabilities",
        "status",
        existing_type=sa.VARCHAR(length=50),
        type_=sa.Enum("open", "fixed", name="vulnerability_status", native_enum=False),
        existing_nullable=False,
    )
    op.alter_column(
        "sboms",
        "format",
        existing_type=sa.VARCHAR(length=50),
        type_=sa.Enum("cyclonedx", "spdx", name="sbom_format", native_enum=False),
        existing_nullable=True,
    )
    op.alter_column(
        "vulnerabilities",
        "severity",
        existing_type=sa.VARCHAR(length=20),
        type_=sa.Enum(
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN",
            name="vulnerability_severity",
            native_enum=False,
        ),
        existing_nullable=True,
    )


def downgrade() -> None:  # pragma: no cover - rollback path, never exercised by tests
    op.alter_column(
        "vulnerabilities",
        "severity",
        existing_type=sa.Enum(
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "UNKNOWN",
            name="vulnerability_severity",
            native_enum=False,
        ),
        type_=sa.VARCHAR(length=20),
        existing_nullable=True,
    )
    op.alter_column(
        "sboms",
        "format",
        existing_type=sa.Enum("cyclonedx", "spdx", name="sbom_format", native_enum=False),
        type_=sa.VARCHAR(length=50),
        existing_nullable=True,
    )
    op.alter_column(
        "sbom_vulnerabilities",
        "status",
        existing_type=sa.Enum("open", "fixed", name="vulnerability_status", native_enum=False),
        type_=sa.VARCHAR(length=50),
        existing_nullable=False,
    )
    op.alter_column(
        "pull_requests",
        "status",
        existing_type=sa.Enum("open", name="pull_request_status", native_enum=False),
        type_=sa.VARCHAR(length=50),
        existing_nullable=False,
    )
    op.alter_column(
        "notifications",
        "status",
        existing_type=sa.Enum(
            "sent", "failed", "resolved", name="notification_status", native_enum=False
        ),
        type_=sa.VARCHAR(length=50),
        existing_nullable=False,
    )
    op.alter_column(
        "notifications",
        "channel",
        existing_type=sa.Enum("email", "slack", name="notification_channel", native_enum=False),
        type_=sa.VARCHAR(length=50),
        existing_nullable=True,
    )
    op.alter_column(
        "alert_configs",
        "notification_type",
        existing_type=sa.Enum("email", "slack", name="notification_channel", native_enum=False),
        type_=sa.VARCHAR(length=50),
        existing_nullable=False,
    )
    op.alter_column(
        "alert_configs",
        "severity_threshold",
        existing_type=sa.Enum(
            "critical", "high", "medium", "low", name="severity_threshold", native_enum=False
        ),
        type_=sa.VARCHAR(length=20),
        existing_nullable=False,
    )
