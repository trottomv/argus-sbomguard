"""add surrogate id to sbom_vulnerabilities and episode link to notifications

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-08

Notifications are deduplicated per vulnerability "episode" (the period a
vulnerability stays open): a fixed-then-reopened vulnerability alerts
again. To reference the episode, ``notifications`` needs a stable handle
on a single ``sbom_vulnerabilities`` row, which the composite PK cannot
provide, so ``sbom_vulnerabilities`` gains a surrogate UUID primary key
and the unique scope constraint moves to the old composite.

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
    op.drop_constraint("sbom_vulnerabilities_pkey", "sbom_vulnerabilities", type_="primary")
    op.add_column("sbom_vulnerabilities", sa.Column("id", sa.Uuid(), nullable=True))
    op.execute("UPDATE sbom_vulnerabilities SET id = gen_random_uuid()")
    op.alter_column("sbom_vulnerabilities", "id", nullable=False)
    op.create_primary_key("sbom_vulnerabilities_pkey", "sbom_vulnerabilities", ["id"])
    op.create_unique_constraint(
        "uq_sbom_vulnerabilities_scope",
        "sbom_vulnerabilities",
        ["sbom_id", "dependency_purl", "vulnerability_id"],
    )

    op.add_column(
        "notifications",
        sa.Column("sbom_vulnerability_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_notifications_sbom_vulnerability",
        "notifications",
        "sbom_vulnerabilities",
        ["sbom_vulnerability_id"],
        ["id"],
    )
    op.add_column("notifications", sa.Column("episode_link_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("notifications", "episode_link_ids")
    op.drop_constraint("fk_notifications_sbom_vulnerability", "notifications", type_="foreignkey")
    op.drop_column("notifications", "sbom_vulnerability_id")

    op.drop_constraint("uq_sbom_vulnerabilities_scope", "sbom_vulnerabilities", type_="unique")
    op.drop_constraint("sbom_vulnerabilities_pkey", "sbom_vulnerabilities", type_="primary")
    op.create_primary_key(
        "sbom_vulnerabilities_pkey",
        "sbom_vulnerabilities",
        ["sbom_id", "dependency_purl", "vulnerability_id"],
    )
    op.drop_column("sbom_vulnerabilities", "id")
