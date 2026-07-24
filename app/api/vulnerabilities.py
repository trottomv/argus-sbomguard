from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.api_key import api_key_required
from models.sbom import SBOM
from models.service import Service
from models.vulnerability import SBOMVulnerability, Vulnerability
from services.pagination import VULN_PER_PAGE, Page, paginate

router = APIRouter(
    prefix="/api/v1/vulnerabilities",
    tags=["vulnerabilities"],
    dependencies=[Depends(api_key_required)],
)


@router.get("/active")
async def active_vulnerabilities(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(VULN_PER_PAGE, ge=1, le=200),
    severity: str = Query(None),
    project_id: str = Query(None),
    service_id: str = Query(None),
    sort: str = Query("cvss_score"),
    order: str = Query("desc"),
):
    subq = (
        select(Vulnerability.id).join(SBOMVulnerability).where(SBOMVulnerability.status == "open")
    )
    if severity and severity != "":
        subq = subq.where(Vulnerability.severity.ilike(severity))
    if (project_id and project_id != "") or (service_id and service_id != ""):
        subq = subq.join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
        if project_id and project_id != "":
            subq = subq.where(SBOM.project_id == project_id)
        if service_id and service_id != "":
            subq = subq.where(SBOM.service_id == service_id)
    subq = subq.distinct()

    query = select(Vulnerability).where(Vulnerability.id.in_(subq))

    sort_map = {
        "severity": func.lower(Vulnerability.severity),
        "cvss_score": Vulnerability.cvss_score,
        "published_at": Vulnerability.published_at,
    }
    sort_col = sort_map.get(sort, Vulnerability.cvss_score)

    if sort == "severity":
        from sqlalchemy import case

        severity_case = case(
            (Vulnerability.severity == "CRITICAL", 0),
            (Vulnerability.severity == "HIGH", 1),
            (Vulnerability.severity == "MEDIUM", 2),
            (Vulnerability.severity == "LOW", 3),
            else_=99,
        )
        if order == "asc":
            query = query.order_by(severity_case.asc(), Vulnerability.cvss_score.desc().nullslast())
        else:
            query = query.order_by(
                severity_case.desc(), Vulnerability.cvss_score.desc().nullslast()
            )
    else:
        if order == "asc":
            query = query.order_by(
                sort_col.asc().nullslast(), Vulnerability.cvss_score.desc().nullslast()
            )
        else:
            query = query.order_by(
                sort_col.desc().nullslast(), Vulnerability.cvss_score.desc().nullslast()
            )

    pg: Page = await paginate(db, query, page=page, per_page=per_page)

    vuln_ids = [v.id for v in pg.items]
    project_map: dict[str, set[str]] = {}
    service_map: dict[str, set[str]] = {}
    if vuln_ids:
        proj_rows = await db.execute(
            select(SBOMVulnerability.vulnerability_id, SBOM.project_id.label("name"))
            .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
            .where(SBOMVulnerability.vulnerability_id.in_(vuln_ids))
        )
        proj_ids = {row[1] for row in proj_rows}
        proj_lines = {}
        if proj_ids:
            from models.project import Project

            proj_lines_rows = await db.execute(
                select(Project.id, Project.name).where(Project.id.in_(proj_ids))
            )
            proj_lines = {str(p_id): p_name for p_id, p_name in proj_lines_rows}

        for v_id, p_id in proj_rows:
            p_name = proj_lines.get(str(p_id), "")
            if p_name:
                project_map.setdefault(v_id, set()).add(p_name)

        svc_rows = await db.execute(
            select(SBOMVulnerability.vulnerability_id, Service.name)
            .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
            .outerjoin(Service, SBOM.service_id == Service.id)
            .where(SBOMVulnerability.vulnerability_id.in_(vuln_ids))
        )
        for v_id, svc_name in svc_rows:
            if svc_name:
                service_map.setdefault(v_id, set()).add(svc_name)

    return {
        "items": [
            {
                "id": str(v.id),
                "cve_id": v.cve_id,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "summary": v.summary,
                "source": v.source,
                "published_at": v.published_at.isoformat() if v.published_at else None,
                "projects": sorted(project_map.get(v.id, [])),
                "services": sorted(service_map.get(v.id, [])),
            }
            for v in pg.items
        ],
        "total": pg.total,
        "page": pg.page,
        "per_page": pg.per_page,
        "total_pages": pg.total_pages,
    }


@router.get("/summary")
async def vulnerability_summary(db: AsyncSession = Depends(get_db)):
    vuln_subq = (
        select(Vulnerability.id, Vulnerability.severity)
        .join(SBOMVulnerability)
        .where(SBOMVulnerability.status == "open")
        .distinct()
    ).subquery()

    vuln_counts = await db.execute(
        select(
            func.count().filter(vuln_subq.c.severity.ilike("critical")).label("critical"),
            func.count().filter(vuln_subq.c.severity.ilike("high")).label("high"),
            func.count().filter(vuln_subq.c.severity.ilike("medium")).label("medium"),
            func.count().filter(vuln_subq.c.severity.ilike("low")).label("low"),
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
            .where(SBOMVulnerability.status == "open")
            .subquery()
        )
    )

    return {
        "counts": counts,
        "total": sum(counts.values()),
        "affected_projects": affected.scalar() or 0,
    }
