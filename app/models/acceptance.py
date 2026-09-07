import uuid

from sqlalchemy import ForeignKey, Index, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from models.base import BaseModel


class RiskAcceptance(BaseModel):
    """A per-scope "won't fix" decision for a vulnerability.

    The scope mirrors the exposure scope of an SBOM finding: a row with
    ``service_id`` NULL accepts the vulnerability across the whole project
    (covering project-scoped SBOMs and every service of the project); a row
    with ``service_id`` set accepts it for that service only. Two partial
    unique indexes keep one acceptance per ``(project, service, vulnerability)``
    (PostgreSQL treats NULLs as distinct in a plain unique constraint).
    """

    __tablename__ = "risk_acceptances"
    __table_args__ = (
        Index(
            "uq_risk_acceptances_project_vuln",
            "project_id",
            "vulnerability_id",
            unique=True,
            postgresql_where=text("service_id IS NULL"),
        ),
        Index(
            "uq_risk_acceptances_service_vuln",
            "project_id",
            "service_id",
            "vulnerability_id",
            unique=True,
            postgresql_where=text("service_id IS NOT NULL"),
        ),
    )

    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    service_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("services.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
