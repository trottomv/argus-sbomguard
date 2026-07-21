import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.database import get_db
from app.models.sbom import SBOM
from app.models.vulnerability import SBOMVulnerability, Vulnerability

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])


@router.get("/active")
async def active_vulnerabilities(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Vulnerability)
        .join(SBOMVulnerability)
        .where(SBOMVulnerability.status == "open")
        .distinct()
        .order_by(Vulnerability.cvss_score.desc().nullslast())
    )
    vulns = result.scalars().all()

    return {
        "vulnerabilities": [
            {
                "id": str(v.id),
                "cve_id": v.cve_id,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "summary": v.summary,
                "source": v.source,
                "published_at": v.published_at.isoformat() if v.published_at else None,
            }
            for v in vulns
        ],
        "total": len(vulns),
    }


@router.get("/summary")
async def vulnerability_summary(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Vulnerability)
        .join(SBOMVulnerability)
        .where(SBOMVulnerability.status == "open")
        .distinct()
    )
    vulns = result.scalars().all()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for v in vulns:
        sev = v.severity.lower() if v.severity else "unknown"
        counts[sev] = counts.get(sev, 0) + 1

    affected = await db.execute(
        select(SBOM.project_id).distinct()
        .join(SBOMVulnerability)
        .where(SBOMVulnerability.status == "open")
    )

    return {
        "counts": counts,
        "total": sum(counts.values()),
        "affected_projects": len(affected.scalars().all()),
    }
