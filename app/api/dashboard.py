import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.alert import AlertConfig, NotificationChannel, SeverityThreshold
from models.project import Project
from models.sbom import SBOM, Dependency
from models.service import Service
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)
from services.auth import create_api_key, list_api_keys, revoke_api_key
from services.pagination import (
    PROJECT_PER_PAGE,
    PROJECT_SBOM_HISTORY_PER_PAGE,
    PROJECT_VULN_PER_PAGE,
    SBOM_PER_PAGE,
    VULN_PER_PAGE,
    Page,
    paginate,
)
from services.tasks import snapshot_metrics
from templating import format_dt, templates

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _dep_name(name: str | None, version: str | None, purl: str | None) -> str:
    if name:
        return f"{name} {version}" if version else name
    if purl:
        parts = purl.split("/")
        last = parts[-1].split("?")[0] if len(parts) >= 2 else purl
        if "@" in last:
            pkg, ver = last.split("@", 1)
            return f"{pkg} {ver}"
        return last
    return "-"


def _build_vuln_subquery(severity: str | None, project_id: str | None, service_id: str | None):
    subq = (
        select(Vulnerability.id)
        .join(SBOMVulnerability)
        .where(SBOMVulnerability.status == VulnerabilityStatus.OPEN)
    )
    if severity and severity != "":
        subq = subq.where(Vulnerability.severity.ilike(severity))
    if (project_id and project_id != "") or (service_id and service_id != ""):
        subq = subq.join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
        if project_id and project_id != "":
            subq = subq.where(SBOM.project_id == project_id)
        if service_id and service_id != "":
            subq = subq.where(SBOM.service_id == service_id)
    return subq.distinct()


def _apply_vuln_ordering(query, sort: str, order: str):
    sort_map = {
        "severity": func.lower(Vulnerability.severity),
        "cvss_score": Vulnerability.cvss_score,
        "published_at": Vulnerability.published_at,
    }
    sort_col = sort_map.get(sort, Vulnerability.cvss_score)
    if sort == "severity":
        severity_case = case(
            (Vulnerability.severity == VulnerabilitySeverity.CRITICAL.value, 0),
            (Vulnerability.severity == VulnerabilitySeverity.HIGH.value, 1),
            (Vulnerability.severity == VulnerabilitySeverity.MEDIUM.value, 2),
            (Vulnerability.severity == VulnerabilitySeverity.LOW.value, 3),
            else_=99,
        )
        if order == "asc":
            return query.order_by(severity_case.asc(), Vulnerability.cvss_score.desc().nullslast())
        return query.order_by(severity_case.desc(), Vulnerability.cvss_score.desc().nullslast())
    if order == "asc":
        return query.order_by(
            sort_col.asc().nullslast(), Vulnerability.cvss_score.desc().nullslast()
        )
    return query.order_by(sort_col.desc().nullslast(), Vulnerability.cvss_score.desc().nullslast())


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
                "dependency_name": _dep_name(row.name, row.version, row.dependency_purl),
                "cvss_vector": cvss_vec,
                "published": format_dt(row.published_at, "%Y-%m-%d", ""),
                "urls": urls,
                "fix_versions": fix_versions,
            }
        )
    return result


router = APIRouter(tags=["dashboard"])


@router.get("/projects/{project_id}/edit-name", response_class=HTMLResponse)
async def edit_project_name(request: Request, project_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return HTMLResponse("", status_code=404)

    return templates.TemplateResponse(
        request,
        "partials/edit_project_name.html",
        {"project": project},
    )


@router.get("/projects/{project_id}/cancel-edit-name", response_class=HTMLResponse)
async def cancel_edit_project_name(
    request: Request, project_id: str, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return HTMLResponse("", status_code=404)

    return templates.TemplateResponse(
        request,
        "partials/project_name_display.html",
        {"project": project},
    )


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

    return templates.TemplateResponse(
        request,
        "partials/project_name_display.html",
        {"project": project},
    )


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    project_count = (await db.execute(select(func.count(Project.id)))).scalar() or 0
    sbom_count = (await db.execute(select(func.count(SBOM.id)))).scalar() or 0

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

    fixed_count = (
        await db.execute(
            select(func.count(SBOMVulnerability.vulnerability_id)).where(
                SBOMVulnerability.status == VulnerabilityStatus.FIXED
            )
        )
    ).scalar() or 0

    recent_result = await db.execute(
        select(SBOM, Project.name, Service.name)
        .outerjoin(Service, SBOM.service_id == Service.id)
        .join(Project, SBOM.project_id == Project.id)
        .order_by(SBOM.uploaded_at.desc())
        .limit(5)
    )
    recent_sboms = recent_result.all()

    snapshots = await db.execute(
        select(
            VulnerabilitySnapshot.snapshot_date,
            func.sum(VulnerabilitySnapshot.critical_count).label("critical"),
            func.sum(VulnerabilitySnapshot.high_count).label("high"),
            func.sum(VulnerabilitySnapshot.medium_count).label("medium"),
            func.sum(VulnerabilitySnapshot.low_count).label("low"),
            func.sum(VulnerabilitySnapshot.fixed_count).label("fixed"),
        )
        .group_by(VulnerabilitySnapshot.snapshot_date)
        .order_by(VulnerabilitySnapshot.snapshot_date.asc())
        .limit(30)
    )
    snap_rows = snapshots.all()

    chart_labels = [snap.snapshot_date.strftime("%b %d") for snap in snap_rows]
    chart_critical = [snap.critical or 0 for snap in snap_rows]
    chart_high = [snap.high or 0 for snap in snap_rows]
    chart_medium = [snap.medium or 0 for snap in snap_rows]
    chart_low = [snap.low or 0 for snap in snap_rows]
    chart_fixed = [snap.fixed or 0 for snap in snap_rows]

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "project_count": project_count,
            "sbom_count": sbom_count,
            "critical": row.critical or 0,
            "high": row.high or 0,
            "medium": row.medium or 0,
            "low": row.low or 0,
            "fixed_count": fixed_count,
            "recent_sboms": recent_sboms,
            "chart_labels": chart_labels,
            "chart_critical": chart_critical,
            "chart_high": chart_high,
            "chart_medium": chart_medium,
            "chart_low": chart_low,
            "chart_fixed": chart_fixed,
        },
    )


@router.post("/refresh-snapshots", status_code=202)
async def refresh_snapshots():
    snapshot_metrics.delay()
    return Response(status_code=202)


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

    return templates.TemplateResponse(
        request,
        "projects/detail.html",
        {
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
        },
    )


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

    if page > 1:
        return templates.TemplateResponse(request, "projects/vuln_rows_partial.html", ctx)

    return templates.TemplateResponse(request, "projects/vuln_rows_partial.html", ctx)


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
        Vulnerability.id.in_(_build_vuln_subquery(severity, project_id, service_id))
    )
    query = _apply_vuln_ordering(query, sort, order)

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
        for vuln_id, dep_name, dep_version, dep_purl in dep_rows:
            dep_map.setdefault(vuln_id, set()).add(_dep_name(dep_name, dep_version, dep_purl))
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


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: AsyncSession = Depends(get_db)):
    projects = (await db.execute(select(Project).order_by(Project.name))).scalars().all()
    alerts = (
        (await db.execute(select(AlertConfig).order_by(AlertConfig.created_at.desc())))
        .scalars()
        .all()
    )
    api_keys = await list_api_keys(db)
    project_names = {str(project.id): project.name for project in projects}
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "projects": projects,
            "alerts": alerts,
            "api_keys": api_keys,
            "project_names": project_names,
            "severity_thresholds": list(SeverityThreshold),
            "notification_channels": list(NotificationChannel),
        },
    )


@router.post("/settings/api-keys", response_class=HTMLResponse)
async def create_api_key_web(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    user = getattr(request.state, "user", None)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    form = await request.form()
    label = form.get("label", "")

    key, raw = await create_api_key(db, uuid.UUID(user.id), label=str(label))
    await db.commit()

    api_keys = await list_api_keys(db)
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "projects": [],
            "alerts": [],
            "api_keys": api_keys,
            "new_key": raw,
            "new_key_prefix": key.key_prefix,
        },
    )


@router.delete("/settings/api-keys/{key_id}", status_code=204)
async def revoke_api_key_web(
    key_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    await revoke_api_key(db, key_id)
    await db.commit()


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
