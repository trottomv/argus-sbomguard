"""switch JSONB to JSON

Revision ID: 002
Revises: 001
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("sboms", "raw_sbom", type_=sa.JSON(), postgresql_using="raw_sbom::json")
    op.alter_column("dependencies", "extra_data", type_=sa.JSON(), postgresql_using="extra_data::json")
    op.alter_column("vulnerabilities", "affected_packages", type_=sa.JSON(), postgresql_using="affected_packages::json")
    op.alter_column("vulnerabilities", "fixed_versions", type_=sa.JSON(), postgresql_using="fixed_versions::json")
    op.alter_column("vulnerabilities", "extra_data", type_=sa.JSON(), postgresql_using="extra_data::json")
    op.alter_column("vulnerability_snapshots", "metrics", type_=sa.JSON(), postgresql_using="metrics::json")
    op.alter_column("alert_configs", "config", type_=sa.JSON(), postgresql_using="config::json")


def downgrade() -> None:
    op.alter_column("sboms", "raw_sbom", type_=sa.dialects.postgresql.JSONB(), postgresql_using="raw_sbom::jsonb")
    op.alter_column("dependencies", "extra_data", type_=sa.dialects.postgresql.JSONB(), postgresql_using="extra_data::jsonb")
    op.alter_column("vulnerabilities", "affected_packages", type_=sa.dialects.postgresql.JSONB(), postgresql_using="affected_packages::jsonb")
    op.alter_column("vulnerabilities", "fixed_versions", type_=sa.dialects.postgresql.JSONB(), postgresql_using="fixed_versions::jsonb")
    op.alter_column("vulnerabilities", "extra_data", type_=sa.dialects.postgresql.JSONB(), postgresql_using="extra_data::jsonb")
    op.alter_column("vulnerability_snapshots", "metrics", type_=sa.dialects.postgresql.JSONB(), postgresql_using="metrics::jsonb")
    op.alter_column("alert_configs", "config", type_=sa.dialects.postgresql.JSONB(), postgresql_using="config::jsonb")
