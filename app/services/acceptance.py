from datetime import datetime

from sqlalchemy import Exists, exists, or_

from models.acceptance import RiskAcceptance


def covered_by_acceptance(link, sbom, *, not_after: datetime | None = None) -> Exists:
    """Return an ``exists()`` predicate matching a covering acceptance.

    ``link`` is an ``SBOMVulnerability``-shaped selectable and ``sbom`` the
    ``SBOM`` it joins to. A project-level acceptance (``service_id IS NULL``)
    covers every finding of the project; a service-level acceptance only covers
    the SBOMs uploaded against that service. With ``not_after`` set, only
    acceptances created at or before that instant are considered (used when
    reconstructing a historical day in the snapshot trend).

    Usage: ``.where(~covered_by_acceptance(SBOMVulnerability, SBOM))`` to keep
    only "actionable" open findings — those no user has accepted.
    """
    conditions = [
        RiskAcceptance.vulnerability_id == link.vulnerability_id,
        RiskAcceptance.project_id == sbom.project_id,
        or_(
            RiskAcceptance.service_id.is_(None),
            RiskAcceptance.service_id == sbom.service_id,
        ),
    ]
    if not_after is not None:
        conditions.append(RiskAcceptance.created_at <= not_after)
    return exists().where(*conditions)
