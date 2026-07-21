"""initial schema

Revision ID: 001
Revises:
Create Date: 2026-07-21
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False, index=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("repo_url", sa.String(1024), nullable=True),
        sa.Column("platform", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "sboms",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("projects.id"), nullable=False, index=True),
        sa.Column("version", sa.String(255), nullable=True),
        sa.Column("format", sa.String(50), nullable=True),
        sa.Column("raw_sbom", postgresql.JSONB(), nullable=False),
        sa.Column("sha256", sa.String(64), unique=True, nullable=False),
        sa.Column("dependency_count", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "dependencies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sbom_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sboms.id"), nullable=False, index=True),
        sa.Column("name", sa.String(512), nullable=False),
        sa.Column("version", sa.String(255), nullable=False),
        sa.Column("purl", sa.String(1024), nullable=True),
        sa.Column("dep_type", sa.String(50), nullable=True),
        sa.Column("license", sa.String(255), nullable=True),
        sa.Column("is_direct", sa.Boolean(), default=False),
        sa.Column("extra_data", postgresql.JSONB(), default=dict),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cve_id", sa.String(50), unique=True, nullable=False, index=True),
        sa.Column("source", sa.String(50), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True, index=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("affected_packages", postgresql.JSONB(), default=dict),
        sa.Column("fixed_versions", postgresql.JSONB(), default=dict),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("extra_data", postgresql.JSONB(), default=dict),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "sbom_vulnerabilities",
        sa.Column("sbom_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sboms.id"), primary_key=True),
        sa.Column("dependency_purl", sa.String(1024), primary_key=True),
        sa.Column("vulnerability_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("vulnerabilities.id"), primary_key=True),
        sa.Column("status", sa.String(50), default="open"),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "alert_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("projects.id"), nullable=False, index=True),
        sa.Column("severity_threshold", sa.String(20), default="high"),
        sa.Column("notification_type", sa.String(50), default="slack"),
        sa.Column("config", postgresql.JSONB(), default=dict),
        sa.Column("enabled", sa.Boolean(), default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_config_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alert_configs.id"), nullable=False),
        sa.Column("vulnerability_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("channel", sa.String(50), nullable=True),
        sa.Column("status", sa.String(50), default="sent"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "pull_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("projects.id"), nullable=False, index=True),
        sa.Column("dependency_name", sa.String(512), nullable=False),
        sa.Column("from_version", sa.String(255), nullable=False),
        sa.Column("to_version", sa.String(255), nullable=False),
        sa.Column("pr_url", sa.String(1024), nullable=True),
        sa.Column("status", sa.String(50), default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "vulnerability_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("critical_count", sa.Integer(), default=0),
        sa.Column("high_count", sa.Integer(), default=0),
        sa.Column("medium_count", sa.Integer(), default=0),
        sa.Column("low_count", sa.Integer(), default=0),
        sa.Column("total_dependencies", sa.Integer(), default=0),
        sa.Column("metrics", postgresql.JSONB(), default=dict),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("project_id", "snapshot_date"),
    )


def downgrade() -> None:
    op.drop_table("vulnerability_snapshots")
    op.drop_table("pull_requests")
    op.drop_table("notifications")
    op.drop_table("alert_configs")
    op.drop_table("sbom_vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_table("dependencies")
    op.drop_table("sboms")
    op.drop_table("projects")
