from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.pages.common import dep_name
from database import get_db
from models.project import Project
from models.sbom import SBOM, Dependency
from models.service import Service
from models.vulnerability import SBOMVulnerability, Vulnerability, VulnerabilityStatus
from services.pagination import VULN_PER_PAGE, Page, paginate
from services.vulnerability_queries import apply_vuln_ordering, build_vuln_subquery
from templating import templates

router = APIRouter(tags=["vulnerabilities"], include_in_schema=False)


@router.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    severity: str = Query(None),
    project_id: str = Query(None),
    service_id: str = Query(None),
    sort: str = Query("cvss_score"),
    order: str = Query("desc"),
    page: int = Query(1, ge=1),
    per_page: int = Query(VULN_PER_PAGE, ge=1, le=200),
):
    query = select(Vulnerability).where(
        Vulnerability.id.in_(build_vuln_subquery(severity, project_id, service_id))
    )
    query = apply_vuln_ordering(query, sort, order)

    pg: Page = await paginate(db, query, page=page, per_page=per_page)
    vulns = pg.items

    project_map: dict = {}
    service_map: dict = {}
    if vulns:
        vuln_ids = [vuln.id for vuln in vulns]
        proj_rows = await db.execute(
            select(SBOMVulnerability.vulnerability_id, Project.name)
            .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
            .join(Project, SBOM.project_id == Project.id)
            .where(SBOMVulnerability.vulnerability_id.in_(vuln_ids))
        )
        for vuln_id, project_name in proj_rows:
            project_map.setdefault(vuln_id, set()).add(project_name)

        svc_rows = await db.execute(
            select(SBOMVulnerability.vulnerability_id, Service.name)
            .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
            .outerjoin(Service, SBOM.service_id == Service.id)
            .where(SBOMVulnerability.vulnerability_id.in_(vuln_ids))
        )
        for vuln_id, service_name in svc_rows:
            if service_name:
                service_map.setdefault(vuln_id, set()).add(service_name)

        dep_map: dict = {}
        dep_rows = await db.execute(
            select(
                SBOMVulnerability.vulnerability_id,
                Dependency.name,
                Dependency.version,
                SBOMVulnerability.dependency_purl,
            )
            .outerjoin(
                Dependency,
                (SBOMVulnerability.sbom_id == Dependency.sbom_id)
                & (SBOMVulnerability.dependency_purl == Dependency.purl),
            )
            .where(
                SBOMVulnerability.vulnerability_id.in_(vuln_ids),
                SBOMVulnerability.status == VulnerabilityStatus.OPEN,
            )
        )
        for vuln_id, dep_nm, dep_version, dep_purl in dep_rows:
            dep_map.setdefault(vuln_id, set()).add(dep_name(dep_nm, dep_version, dep_purl))
        dep_map = {vuln_id: sorted(names) for vuln_id, names in dep_map.items()}

    # Dropdown data: only on first page
    projects: list = []
    services: list = []
    if page == 1:
        projects = (await db.execute(select(Project).order_by(Project.name))).scalars().all()
        services = (
            (
                await db.execute(
                    select(Service).where(Service.project_id == project_id).order_by(Service.name)
                    if project_id and project_id != ""
                    else select(Service).order_by(Service.name)
                )
            )
            .scalars()
            .all()
        )

    load_more_url = (
        f"/vulnerabilities?severity={severity or ''}&project_id={project_id or ''}"
        f"&service_id={service_id or ''}&sort={sort}&order={order}&per_page={per_page}"
    )

    ctx = {
        "items": vulns,
        "project_map": project_map,
        "service_map": service_map,
        "dep_map": dep_map if vulns else {},
        "projects": projects,
        "services": services,
        "active_severity": severity or "",
        "active_project_id": project_id or "",
        "active_service_id": service_id or "",
        "active_sort": sort,
        "active_order": order,
        "total": pg.total,
        "page": pg.page,
        "per_page": pg.per_page,
        "total_pages": pg.total_pages,
        "has_more": pg.has_more,
        "target": "vuln",
        "load_more_url": load_more_url,
    }

    if page > 1:
        return templates.TemplateResponse(request, "vulnerabilities/rows_partial.html", ctx)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "vulnerabilities/page.html", ctx)

    return templates.TemplateResponse(request, "vulnerabilities/list.html", ctx)
