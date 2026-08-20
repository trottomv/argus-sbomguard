import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.pages.common import dep_name
from database import get_db
from models.project import Project
from models.sbom import SBOM, Dependency
from models.service import Service
from models.vulnerability import SBOMVulnerability, Vulnerability, VulnerabilityStatus
from services.pagination import (
    PROJECT_PER_PAGE,
    PROJECT_SBOM_HISTORY_PER_PAGE,
    PROJECT_VULN_PER_PAGE,
    Page,
    paginate,
)
from templating import format_dt, templates

router = APIRouter(tags=["projects"], include_in_schema=False)


async def _get_project_vulns(
    db: AsyncSession, project_id: uuid.UUID, service_id: str | None = None
) -> list[dict]:
    id_q = select(SBOM.id, SBOM.service_id, SBOM.created_at).where(SBOM.project_id == project_id)
    if service_id and service_id != "":
        id_q = id_q.where(SBOM.service_id == service_id)
    all_ids_q = await db.execute(id_q)
    latest_map: dict[str, tuple] = {}
    sbom_to_svc: dict = {}
    for sbom_id, svc_id, created_at in all_ids_q:
        key = str(svc_id) if svc_id else "__no_service__"
        if key not in latest_map or created_at > latest_map[key][1]:
            latest_map[key] = (sbom_id, created_at)
    latest_sbom_ids = {latest[0] for latest in latest_map.values()}

    if not latest_sbom_ids:
        return []

    svc_rows = await db.execute(
        select(SBOM.id, Service.name)
        .outerjoin(Service, SBOM.service_id == Service.id)
        .where(SBOM.id.in_(latest_sbom_ids))
    )
    for sbom_id, service_name in svc_rows:
        if service_name:
            sbom_to_svc[sbom_id] = service_name

    vuln_rows = await db.execute(
        select(
            SBOMVulnerability.sbom_id,
            SBOMVulnerability.dependency_purl,
            Dependency.name,
            Dependency.version,
            Vulnerability.cve_id,
            Vulnerability.severity,
            Vulnerability.cvss_score,
            Vulnerability.summary,
            Vulnerability.published_at,
            Vulnerability.extra_data,
        )
        .join(Vulnerability, SBOMVulnerability.vulnerability_id == Vulnerability.id)
        .outerjoin(
            Dependency,
            (SBOMVulnerability.sbom_id == Dependency.sbom_id)
            & (SBOMVulnerability.dependency_purl == Dependency.purl),
        )
        .where(
            SBOMVulnerability.sbom_id.in_(latest_sbom_ids),
            SBOMVulnerability.status == VulnerabilityStatus.OPEN,
        )
        .order_by(Vulnerability.cvss_score.desc().nullslast())
    )

    seen = set()
    result: list[dict] = []
    for row in vuln_rows:
        if row.cve_id in seen:
            continue
        seen.add(row.cve_id)
        svc_name = sbom_to_svc.get(row.sbom_id)
        ed = row.extra_data or {}
        cvss_list = ed.get("cvss") or []
        cvss_vec = cvss_list[0].get("vector") if cvss_list else ""
        urls = ed.get("urls") or []
        fix_info = ed.get("fix") or {}
        fix_versions = fix_info.get("versions") or []

        result.append(
            {
                "cve_id": row.cve_id,
                "severity": row.severity,
                "cvss_score": row.cvss_score,
                "summary": row.summary,
                "service_name": svc_name,
                "dependency_purl": row.dependency_purl,
                "dependency_name": dep_name(row.name, row.version, row.dependency_purl),
                "cvss_vector": cvss_vec,
                "published": format_dt(row.published_at, "%Y-%m-%d", ""),
                "urls": urls,
                "fix_versions": fix_versions,
            }
        )
    return result


@router.get("/projects/{project_id}/edit-name", response_class=HTMLResponse)
async def edit_project_name(request: Request, project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return HTMLResponse("", status_code=404)

    ctx = {"project": project}
    return templates.TemplateResponse(request, "partials/edit_project_name.html", ctx)


@router.get("/projects/{project_id}/cancel-edit-name", response_class=HTMLResponse)
async def cancel_edit_project_name(
    request: Request, project_id: str, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return HTMLResponse("", status_code=404)

    ctx = {"project": project}
    return templates.TemplateResponse(request, "partials/project_name_display.html", ctx)


@router.patch("/projects/{project_id}/name", response_class=HTMLResponse)
async def update_project_name(
    request: Request,
    project_id: str,
    db: AsyncSession = Depends(get_db),
):
    form = await request.form()
    name = form.get("name", "").strip()
    if not any(char.isalnum() for char in name):
        return HTMLResponse("", status_code=422)

    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return HTMLResponse("", status_code=404)

    existing = await db.execute(
        select(Project).where(Project.name == name, Project.id != uuid.UUID(project_id))
    )
    if existing.scalar_one_or_none():
        return HTMLResponse("", status_code=409)

    project.name = name
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return HTMLResponse("", status_code=409)

    ctx = {"project": project}
    return templates.TemplateResponse(request, "partials/project_name_display.html", ctx)


@router.get("/projects", response_class=HTMLResponse)
async def projects_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(PROJECT_PER_PAGE, ge=1, le=200),
):
    query = select(Project).order_by(Project.created_at.desc())
    pg: Page = await paginate(db, query, page=page, per_page=per_page)

    ctx = {
        "items": pg.items,
        "total": pg.total,
        "page": pg.page,
        "per_page": pg.per_page,
        "total_pages": pg.total_pages,
        "has_more": pg.has_more,
        "target": "project-cards",
        "load_more_url": f"/projects?per_page={per_page}",
        "label": "Load more projects",
    }

    if page > 1:
        return templates.TemplateResponse(request, "projects/rows_partial.html", ctx)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "projects/page.html", ctx)

    return templates.TemplateResponse(request, "projects/list.html", ctx)


@router.get("/projects/{project_id}", response_class=HTMLResponse)
async def project_detail_page(
    request: Request,
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service_id: str = Query(None),
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return RedirectResponse(url="/projects")

    sbom_history_per_page = PROJECT_SBOM_HISTORY_PER_PAGE

    sbom_base = select(SBOM.id).where(SBOM.project_id == project_id)
    if service_id and service_id != "":
        sbom_base = sbom_base.where(SBOM.service_id == service_id)

    total_q = await db.execute(select(func.count()).select_from(sbom_base.subquery()))
    sbom_history_total = total_q.scalar() or 0

    dep_sum_q = await db.execute(
        select(func.coalesce(func.sum(SBOM.dependency_count), 0)).where(
            SBOM.project_id == project_id
        )
    )
    total_dependency_count = dep_sum_q.scalar() or 0

    sboms_query = (
        select(SBOM, Service.name)
        .outerjoin(Service, SBOM.service_id == Service.id)
        .where(SBOM.project_id == project_id)
    )
    if service_id and service_id != "":
        sboms_query = sboms_query.where(SBOM.service_id == service_id)
    sboms_query = sboms_query.order_by(SBOM.created_at.desc()).limit(sbom_history_per_page)

    sbom_rows = (await db.execute(sboms_query)).all()
    sboms_with_svc = [(row[0], row[1]) for row in sbom_rows]
    shown_ids = [row[0].id for row in sbom_rows]

    vulns_by_sbom: dict = {}
    fixed_by_sbom: dict = {}
    if shown_ids:
        vc_rows = await db.execute(
            select(
                SBOMVulnerability.sbom_id,
                SBOMVulnerability.status,
                func.count(SBOMVulnerability.vulnerability_id),
            )
            .where(SBOMVulnerability.sbom_id.in_(shown_ids))
            .group_by(SBOMVulnerability.sbom_id, SBOMVulnerability.status)
        )
        for sbom_id, status, count in vc_rows:
            if status == VulnerabilityStatus.OPEN:
                vulns_by_sbom[sbom_id] = count
            elif status == VulnerabilityStatus.FIXED:
                fixed_by_sbom[sbom_id] = count

    project_vulns_all = await _get_project_vulns(db, project_id, service_id)
    project_vuln_per_page = PROJECT_VULN_PER_PAGE
    project_vuln_total = len(project_vulns_all)
    project_vuln_has_more = project_vuln_total > project_vuln_per_page
    project_vulns = project_vulns_all[:project_vuln_per_page]

    services_result = await db.execute(
        select(Service).where(Service.project_id == project_id).order_by(Service.name)
    )
    services = services_result.scalars().all()

    sbom_history_pages = (
        max(1, (sbom_history_total + sbom_history_per_page - 1) // sbom_history_per_page)
        if sbom_history_total > sbom_history_per_page
        else 1
    )

    ctx = {
        "project": project,
        "sboms_with_svc": sboms_with_svc,
        "services": services,
        "active_service_id": service_id or "",
        "vulns_by_sbom": vulns_by_sbom,
        "fixed_by_sbom": fixed_by_sbom,
        "project_vulns": project_vulns,
        "project_vuln_per_page": project_vuln_per_page,
        "project_vuln_total": project_vuln_total,
        "project_vuln_has_more": project_vuln_has_more,
        "sbom_history_total": sbom_history_total,
        "sbom_history_pages": sbom_history_pages,
        "sbom_history_per_page": sbom_history_per_page,
        "total_dependency_count": total_dependency_count,
    }

    return templates.TemplateResponse(request, "projects/detail.html", ctx)


@router.get("/projects/{project_id}/sboms", response_class=HTMLResponse)
async def project_sboms_page(
    request: Request,
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(PROJECT_SBOM_HISTORY_PER_PAGE, ge=1, le=200),
    service_id: str = Query(None),
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return HTMLResponse("", status_code=404)

    sboms_query = (
        select(SBOM, Service.name)
        .outerjoin(Service, SBOM.service_id == Service.id)
        .where(SBOM.project_id == project_id)
    )
    if service_id and service_id != "":
        sboms_query = sboms_query.where(SBOM.service_id == service_id)
    sboms_query = sboms_query.order_by(SBOM.created_at.desc())

    pg: Page = await paginate(db, sboms_query, page=page, per_page=per_page, scalar=False)
    sbom_ids = [row[0].id for row in pg.items]

    vulns_by_sbom: dict = {}
    fixed_by_sbom: dict = {}
    if sbom_ids:
        vuln_rows = await db.execute(
            select(
                SBOMVulnerability.sbom_id,
                SBOMVulnerability.status,
                func.count(SBOMVulnerability.vulnerability_id),
            )
            .where(SBOMVulnerability.sbom_id.in_(sbom_ids))
            .group_by(SBOMVulnerability.sbom_id, SBOMVulnerability.status)
        )
        for sbom_id, status, count in vuln_rows:
            if status == VulnerabilityStatus.OPEN:
                vulns_by_sbom[sbom_id] = count
            elif status == VulnerabilityStatus.FIXED:
                fixed_by_sbom[sbom_id] = count

    load_url = f"/projects/{project_id}/sboms?per_page={per_page}"
    if service_id:
        load_url += f"&service_id={service_id}"

    ctx = {
        "items": pg.items,
        "vulns_by_sbom": vulns_by_sbom,
        "fixed_by_sbom": fixed_by_sbom,
        "total": pg.total,
        "page": pg.page,
        "per_page": pg.per_page,
        "total_pages": pg.total_pages,
        "has_more": pg.has_more,
        "target": "sbom-history",
        "load_more_url": load_url,
    }

    return templates.TemplateResponse(request, "projects/sbom_history_rows.html", ctx)


@router.get("/projects/{project_id}/vulns", response_class=HTMLResponse)
async def project_vulns_page(
    request: Request,
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(PROJECT_VULN_PER_PAGE, ge=1, le=200),
    service_id: str = Query(None),
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    if not result.scalar_one_or_none():
        return HTMLResponse("", status_code=404)

    all_vulns = await _get_project_vulns(db, project_id, service_id)
    total = len(all_vulns)
    offset = (page - 1) * per_page
    items = all_vulns[offset : offset + per_page]
    has_more = offset + per_page < total

    load_url = f"/projects/{project_id}/vulns?per_page={per_page}"
    if service_id:
        load_url += f"&service_id={service_id}"

    ctx = {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "has_more": has_more,
        "target": "project-vuln",
        "load_more_url": load_url,
    }

    return templates.TemplateResponse(request, "projects/vuln_rows_partial.html", ctx)
