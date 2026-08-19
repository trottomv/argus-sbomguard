from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.project import Project
from models.sbom import SBOM
from models.service import Service
from models.vulnerability import SBOMVulnerability, VulnerabilityStatus
from services.pagination import SBOM_PER_PAGE, Page, paginate
from templating import templates

router = APIRouter(tags=["sboms"])


@router.get("/sboms", response_class=HTMLResponse)
async def sboms_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    sort: str = Query("created_at"),
    order: str = Query("desc"),
    project_id: str = Query(None),
    service_id: str = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(SBOM_PER_PAGE, ge=1, le=200),
):
    query = (
        select(SBOM, Project.name, Service.name)
        .outerjoin(Service, SBOM.service_id == Service.id)
        .join(Project, SBOM.project_id == Project.id)
    )
    if project_id and project_id != "":
        query = query.where(SBOM.project_id == project_id)
    if service_id and service_id != "":
        query = query.where(SBOM.service_id == service_id)

    sort_map = {
        "created_at": SBOM.created_at,
        "deps": SBOM.dependency_count,
        "version": SBOM.version,
        "format": SBOM.format,
    }
    sort_col = sort_map.get(sort, SBOM.created_at)
    if order == "asc":
        query = query.order_by(sort_col.asc().nullslast())
    else:
        query = query.order_by(sort_col.desc().nullslast())

    pg: Page = await paginate(db, query, page=page, per_page=per_page, scalar=False)

    sboms = [(sbom, project_name, service_name) for sbom, project_name, service_name in pg.items]
    sbom_ids = [sbom.id for sbom, _, _ in pg.items]

    vuln_counts = {}
    if sbom_ids:
        vc_rows = await db.execute(
            select(
                SBOMVulnerability.sbom_id,
                func.count(SBOMVulnerability.vulnerability_id),
            )
            .where(
                SBOMVulnerability.sbom_id.in_(sbom_ids),
                SBOMVulnerability.status == VulnerabilityStatus.OPEN,
            )
            .group_by(SBOMVulnerability.sbom_id)
        )
        for sbom_id, count in vc_rows:
            vuln_counts[sbom_id] = count

    # Dropdown data: only on first page
    projects_all: list = []
    services_all: list = []
    if page == 1:
        projects_all = (await db.execute(select(Project).order_by(Project.name))).scalars().all()
        services_all = (
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
        f"/sboms?sort={sort}&order={order}&project_id={project_id or ''}"
        f"&service_id={service_id or ''}&per_page={per_page}"
    )

    ctx = {
        "items": sboms,
        "vuln_counts": vuln_counts,
        "projects": projects_all,
        "services": services_all,
        "active_sort": sort,
        "active_order": order,
        "active_project_id": project_id or "",
        "active_service_id": service_id or "",
        "total": pg.total,
        "page": pg.page,
        "per_page": pg.per_page,
        "total_pages": pg.total_pages,
        "has_more": pg.has_more,
        "target": "sbom",
        "load_more_url": load_more_url,
    }

    if page > 1:
        return templates.TemplateResponse(request, "sboms/rows_partial.html", ctx)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "sboms/page.html", ctx)

    return templates.TemplateResponse(request, "sboms/list.html", ctx)
