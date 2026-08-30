import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.constants import API_V1_PREFIX
from api.v1.schemas import (
    UNAUTHORIZED_RESPONSE,
    PageResponse,
    VulnerabilityResponse,
    VulnerabilitySummaryResponse,
)
from database import get_db
from middleware.api_key import api_key_required
from models.sbom import SBOM
from models.service import Service
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from services.pagination import VULN_PER_PAGE, Page, paginate
from services.vulnerability_queries import apply_vuln_ordering, build_vuln_subquery

router = APIRouter(
    prefix=f"{API_V1_PREFIX}/vulnerabilities",
    tags=["vulnerabilities"],
    dependencies=[Depends(api_key_required)],
)


@router.get(
    "/active",
    response_model=PageResponse[VulnerabilityResponse],
    responses={**UNAUTHORIZED_RESPONSE},
)
async def active_vulnerabilities(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(VULN_PER_PAGE, ge=1, le=200),
    severity: str = Query(None),
    project_id: uuid.UUID | None = Query(None),
    service_id: uuid.UUID | None = Query(None),
    cve_id: str = Query(None),
    sort: str = Query("cvss_score"),
    order: str = Query("desc"),
):
    query = select(Vulnerability).where(
        Vulnerability.id.in_(build_vuln_subquery(severity, project_id, service_id, cve_id))
    )
    query = apply_vuln_ordering(query, sort, order)

    pg: Page = await paginate(db, query, page=page, per_page=per_page)

    vuln_ids = [vuln.id for vuln in pg.items]
    project_map: dict[str, set[str]] = {}
    service_map: dict[str, set[str]] = {}
    if vuln_ids:
        proj_rows = (
            await db.execute(
                select(SBOMVulnerability.vulnerability_id, SBOM.project_id.label("name"))
                .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
                .where(
                    SBOMVulnerability.status == VulnerabilityStatus.OPEN,
                    SBOMVulnerability.vulnerability_id.in_(vuln_ids),
                )
            )
        ).all()
        proj_ids = {row[1] for row in proj_rows}
        proj_lines = {}
        if proj_ids:
            from models.project import Project

            proj_lines_rows = await db.execute(
                select(Project.id, Project.name).where(Project.id.in_(proj_ids))
            )
            proj_lines = {
                str(project_id): project_name for project_id, project_name in proj_lines_rows
            }

        for vuln_id, project_id in proj_rows:
            project_name = proj_lines.get(str(project_id), "")
            if project_name:
                project_map.setdefault(vuln_id, set()).add(project_name)

        svc_rows = await db.execute(
            select(SBOMVulnerability.vulnerability_id, Service.name)
            .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
            .outerjoin(Service, SBOM.service_id == Service.id)
            .where(
                SBOMVulnerability.status == VulnerabilityStatus.OPEN,
                SBOMVulnerability.vulnerability_id.in_(vuln_ids),
            )
        )
        for vuln_id, service_name in svc_rows:
            if service_name:
                service_map.setdefault(vuln_id, set()).add(service_name)

    return PageResponse[VulnerabilityResponse](
        items=[
            VulnerabilityResponse(
                id=vuln.id,
                cve_id=vuln.cve_id,
                severity=vuln.severity,
                cvss_score=vuln.cvss_score,
                summary=vuln.summary,
                source=vuln.source,
                published_at=vuln.published_at,
                projects=sorted(project_map.get(vuln.id, [])),
                services=sorted(service_map.get(vuln.id, [])),
            )
            for vuln in pg.items
        ],
        total=pg.total,
        page=pg.page,
        per_page=pg.per_page,
        total_pages=pg.total_pages,
        has_more=pg.has_more,
    )


@router.get(
    "/summary",
    response_model=VulnerabilitySummaryResponse,
    responses={**UNAUTHORIZED_RESPONSE},
)
async def vulnerability_summary(db: AsyncSession = Depends(get_db)):
    vuln_subq = (
        select(Vulnerability.id, Vulnerability.severity)
        .join(SBOMVulnerability)
        .where(SBOMVulnerability.status == VulnerabilityStatus.OPEN)
        .distinct()
    ).subquery()

    vuln_counts = await db.execute(
        select(
            func.count()
            .filter(vuln_subq.c.severity.ilike(VulnerabilitySeverity.CRITICAL.value))
            .label("critical"),
            func.count()
            .filter(vuln_subq.c.severity.ilike(VulnerabilitySeverity.HIGH.value))
            .label("high"),
            func.count()
            .filter(vuln_subq.c.severity.ilike(VulnerabilitySeverity.MEDIUM.value))
            .label("medium"),
            func.count()
            .filter(vuln_subq.c.severity.ilike(VulnerabilitySeverity.LOW.value))
            .label("low"),
        ).select_from(vuln_subq)
    )
    row = vuln_counts.one()

    counts = {
        "critical": row.critical or 0,
        "high": row.high or 0,
        "medium": row.medium or 0,
        "low": row.low or 0,
        "unknown": 0,
    }

    affected = await db.execute(
        select(func.count()).select_from(
            select(SBOM.project_id.distinct())
            .join(SBOMVulnerability)
            .where(SBOMVulnerability.status == VulnerabilityStatus.OPEN)
            .subquery()
        )
    )

    return VulnerabilitySummaryResponse(
        counts=counts,
        total=sum(counts.values()),
        affected_projects=affected.scalar() or 0,
    )
