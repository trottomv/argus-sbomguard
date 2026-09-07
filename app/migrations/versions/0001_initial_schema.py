"""initial schema (squashed)

Revision ID: 0001
Revises:
Create Date: 2026-09-07

Single-migration schema for the first stable release. All pre-release revisions
(0001..0009) were squashed into this file, so the schema reflects the current
ORM models exactly: the slugify function/unaccent extension backing the
generated ``projects.slug`` column, the alert_rules rename, the EPSS columns on
vulnerabilities and the risk_acceptances table with its partial unique indexes.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # The generated projects.slug column calls public.slugify, so the function
    # (and its unaccent dependency) must exist before the table is created.
    op.execute("CREATE EXTENSION IF NOT EXISTS unaccent")
    op.execute(
        """
        CREATE FUNCTION public.slugify(value text) RETURNS text
        LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
        AS $slug$
            SELECT lower(regexp_replace(
                regexp_replace(public.unaccent(trim(value)), '[^[:alnum:]]+', '-', 'g'),
                '^-+|-+$', '', 'g'))
        $slug$
        """
    )
    op.create_table(
        "projects",
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "slug",
            sa.String(length=255),
            sa.Computed("public.slugify(name)"),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("repo_url", sa.String(length=1024), nullable=True),
        sa.Column("platform", sa.String(length=50), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_projects_name"), "projects", ["name"], unique=True)
    op.create_index(op.f("ix_projects_slug"), "projects", ["slug"], unique=True)
    op.create_table(
        "users",
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("is_admin", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_table(
        "vulnerabilities",
        sa.Column("cve_id", sa.String(length=50), nullable=False),
        sa.Column("source", sa.String(length=50), nullable=True),
        sa.Column(
            "severity",
            sa.Enum(
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNKNOWN",
                name="vulnerability_severity",
                native_enum=False,
            ),
            nullable=True,
        ),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("affected_packages", sa.JSON(), nullable=True),
        sa.Column("fixed_versions", sa.JSON(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("extra_data", sa.JSON(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_vulnerabilities_cve_id"), "vulnerabilities", ["cve_id"], unique=True)
    op.create_index(
        op.f("ix_vulnerabilities_severity"), "vulnerabilities", ["severity"], unique=False
    )
    op.create_table(
        "alert_rules",
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column(
            "severity_threshold",
            sa.Enum(
                "critical", "high", "medium", "low", name="severity_threshold", native_enum=False
            ),
            nullable=False,
        ),
        sa.Column(
            "notification_type",
            sa.Enum("email", "slack", "discord", name="notification_channel", native_enum=False),
            nullable=False,
        ),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_alert_rules_project_id"), "alert_rules", ["project_id"], unique=False)
    op.create_table(
        "api_keys",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("key_prefix", sa.String(length=20), nullable=False),
        sa.Column("key_hash", sa.String(length=255), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_api_keys_key_hash"), "api_keys", ["key_hash"], unique=True)
    op.create_table(
        "login_tokens",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_login_tokens_token_hash"), "login_tokens", ["token_hash"], unique=False
    )
    op.create_table(
        "pull_requests",
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("dependency_name", sa.String(length=512), nullable=False),
        sa.Column("from_version", sa.String(length=255), nullable=False),
        sa.Column("to_version", sa.String(length=255), nullable=False),
        sa.Column("pr_url", sa.String(length=1024), nullable=True),
        sa.Column(
            "status",
            sa.Enum("open", name="pull_request_status", native_enum=False),
            nullable=False,
        ),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_pull_requests_project_id"), "pull_requests", ["project_id"], unique=False
    )
    op.create_table(
        "services",
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "name"),
    )
    op.create_index(op.f("ix_services_project_id"), "services", ["project_id"], unique=False)
    op.create_table(
        "vulnerability_snapshots",
        sa.Column("project_id", sa.Uuid(), nullable=True),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("critical_count", sa.Integer(), nullable=False),
        sa.Column("high_count", sa.Integer(), nullable=False),
        sa.Column("medium_count", sa.Integer(), nullable=False),
        sa.Column("low_count", sa.Integer(), nullable=False),
        sa.Column("fixed_count", sa.Integer(), nullable=False),
        sa.Column("total_dependencies", sa.Integer(), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "snapshot_date"),
    )
    op.create_index(
        "uq_vulnerability_snapshots_global_date",
        "vulnerability_snapshots",
        ["snapshot_date"],
        unique=True,
        postgresql_where=sa.text("project_id IS NULL"),
    )
    op.create_table(
        "notifications",
        sa.Column("alert_rule_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("service_ids", sa.JSON(), nullable=True),
        sa.Column(
            "channel",
            sa.Enum("email", "slack", "discord", name="notification_channel", native_enum=False),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.Enum("sent", "failed", "resolved", name="notification_status", native_enum=False),
            nullable=False,
        ),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["alert_rule_id"], ["alert_rules.id"]),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerabilities.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "risk_acceptances",
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("service_id", sa.Uuid(), nullable=True),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerabilities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_risk_acceptances_project_id"), "risk_acceptances", ["project_id"], unique=False
    )
    op.create_index(
        op.f("ix_risk_acceptances_service_id"), "risk_acceptances", ["service_id"], unique=False
    )
    op.create_index(
        op.f("ix_risk_acceptances_vulnerability_id"),
        "risk_acceptances",
        ["vulnerability_id"],
        unique=False,
    )
    op.create_index(
        "uq_risk_acceptances_project_vuln",
        "risk_acceptances",
        ["project_id", "vulnerability_id"],
        unique=True,
        postgresql_where=sa.text("service_id IS NULL"),
    )
    op.create_index(
        "uq_risk_acceptances_service_vuln",
        "risk_acceptances",
        ["project_id", "service_id", "vulnerability_id"],
        unique=True,
        postgresql_where=sa.text("service_id IS NOT NULL"),
    )
    op.create_table(
        "sboms",
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.String(length=255), nullable=True),
        sa.Column(
            "format",
            sa.Enum("cyclonedx", "spdx", name="sbom_format", native_enum=False),
            nullable=True,
        ),
        sa.Column("raw_sbom", sa.JSON(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("dependency_count", sa.Integer(), nullable=True),
        sa.Column(
            "uploaded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("service_id", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sha256"),
    )
    op.create_index(op.f("ix_sboms_project_id"), "sboms", ["project_id"], unique=False)
    op.create_index(op.f("ix_sboms_service_id"), "sboms", ["service_id"], unique=False)
    op.create_table(
        "dependencies",
        sa.Column("sbom_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("version", sa.String(length=255), nullable=False),
        sa.Column("purl", sa.String(length=1024), nullable=True),
        sa.Column("dep_type", sa.String(length=50), nullable=True),
        sa.Column("license", sa.String(length=255), nullable=True),
        sa.Column("is_direct", sa.Boolean(), nullable=False),
        sa.Column("extra_data", sa.JSON(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["sbom_id"], ["sboms.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dependencies_sbom_id"), "dependencies", ["sbom_id"], unique=False)
    op.create_table(
        "sbom_vulnerabilities",
        sa.Column("sbom_id", sa.Uuid(), nullable=False),
        sa.Column("dependency_purl", sa.String(length=1024), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status",
            sa.Enum("open", "fixed", name="vulnerability_status", native_enum=False),
            nullable=False,
        ),
        sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["sbom_id"], ["sboms.id"]),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerabilities.id"]),
        sa.PrimaryKeyConstraint("sbom_id", "dependency_purl", "vulnerability_id"),
    )


def downgrade() -> None:  # pragma: no cover - rollback path, never exercised by tests
    op.drop_table("sbom_vulnerabilities")
    op.drop_index(op.f("ix_dependencies_sbom_id"), table_name="dependencies")
    op.drop_table("dependencies")
    op.drop_index(op.f("ix_sboms_service_id"), table_name="sboms")
    op.drop_index(op.f("ix_sboms_project_id"), table_name="sboms")
    op.drop_table("sboms")
    op.drop_index(
        "uq_risk_acceptances_service_vuln",
        table_name="risk_acceptances",
        postgresql_where=sa.text("service_id IS NOT NULL"),
    )
    op.drop_index(
        "uq_risk_acceptances_project_vuln",
        table_name="risk_acceptances",
        postgresql_where=sa.text("service_id IS NULL"),
    )
    op.drop_index(op.f("ix_risk_acceptances_vulnerability_id"), table_name="risk_acceptances")
    op.drop_index(op.f("ix_risk_acceptances_service_id"), table_name="risk_acceptances")
    op.drop_index(op.f("ix_risk_acceptances_project_id"), table_name="risk_acceptances")
    op.drop_table("risk_acceptances")
    op.drop_table("notifications")
    op.drop_index(
        "uq_vulnerability_snapshots_global_date",
        table_name="vulnerability_snapshots",
        postgresql_where=sa.text("project_id IS NULL"),
    )
    op.drop_table("vulnerability_snapshots")
    op.drop_index(op.f("ix_services_project_id"), table_name="services")
    op.drop_table("services")
    op.drop_index(op.f("ix_pull_requests_project_id"), table_name="pull_requests")
    op.drop_table("pull_requests")
    op.drop_index(op.f("ix_login_tokens_token_hash"), table_name="login_tokens")
    op.drop_table("login_tokens")
    op.drop_index(op.f("ix_api_keys_key_hash"), table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index(op.f("ix_alert_rules_project_id"), table_name="alert_rules")
    op.drop_table("alert_rules")
    op.drop_index(op.f("ix_vulnerabilities_severity"), table_name="vulnerabilities")
    op.drop_index(op.f("ix_vulnerabilities_cve_id"), table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")
    op.drop_index(op.f("ix_projects_slug"), table_name="projects")
    op.drop_index(op.f("ix_projects_name"), table_name="projects")
    op.drop_table("projects")
    op.execute("DROP FUNCTION IF EXISTS public.slugify(text)")
