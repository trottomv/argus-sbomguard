import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.alert import AlertConfig
from models.project import Project
from models.sbom import SBOM, Dependency
from models.service import Service
from models.vulnerability import SBOMVulnerability, Vulnerability, VulnerabilitySnapshot
from services.auth import create_api_key, list_api_keys, revoke_api_key

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


router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="templates")


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
    if not name:
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
    await db.commit()

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

    fixed_count = (
        await db.execute(
            select(func.count(SBOMVulnerability.vulnerability_id)).where(
                SBOMVulnerability.status == "fixed"
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

    chart_labels = [r.snapshot_date.strftime("%b %d") for r in snap_rows]
    chart_critical = [r.critical or 0 for r in snap_rows]
    chart_high = [r.high or 0 for r in snap_rows]
    chart_medium = [r.medium or 0 for r in snap_rows]
    chart_low = [r.low or 0 for r in snap_rows]
    chart_fixed = [r.fixed or 0 for r in snap_rows]

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


@router.get("/projects", response_class=HTMLResponse)
async def projects_page(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.created_at.desc()))
    projects = result.scalars().all()
    return templates.TemplateResponse(
        request,
        "projects/list.html",
        {"projects": projects},
    )


@router.get("/projects/{project_id}", response_class=HTMLResponse)
async def project_detail_page(
    request: Request,
    project_id: str,
    db: AsyncSession = Depends(get_db),
    service_id: str = Query(None),
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return RedirectResponse(url="/projects")

    sboms_query = (
        select(SBOM, Service.name)
        .outerjoin(Service, SBOM.service_id == Service.id)
        .where(SBOM.project_id == project_id)
    )
    if service_id and service_id != "":
        sboms_query = sboms_query.where(SBOM.service_id == service_id)
    sboms_query = sboms_query.order_by(SBOM.created_at.desc())

    rows = (await db.execute(sboms_query)).all()
    sboms = [r[0] for r in rows]
    svc_names = {r[0].id: r[1] for r in rows if r[1] is not None}

    # For vulnerability stats, keep only the latest SBOM per service
    latest_map: dict[str, SBOM] = {}
    for s in sboms:
        key = str(s.service_id) if s.service_id else "__no_service__"
        if key not in latest_map or s.created_at > latest_map[key].created_at:
            latest_map[key] = s
    latest_sbom_ids = {s.id for s in latest_map.values()}

    sbom_to_svc = {s.id: svc_names.get(s.id) for s in sboms}
    vulns_by_sbom = {}
    fixed_by_sbom = {}
    project_vulns = []
    if sboms:
        all_sbom_ids = [s.id for s in sboms]
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
                SBOMVulnerability.sbom_id.in_(all_sbom_ids),
                SBOMVulnerability.status == "open",
            )
            .order_by(Vulnerability.cvss_score.desc().nullslast())
        )
        seen = set()
        for row in vuln_rows:
            svc_name = sbom_to_svc.get(row.sbom_id)
            svc_name = sbom_to_svc.get(row.sbom_id)
            ed = row.extra_data or {}
            cvss_list = ed.get("cvss") or []
            cvss_vec = cvss_list[0].get("vector") if cvss_list else ""
            urls = ed.get("urls") or []
            fix_info = ed.get("fix") or {}
            fix_versions = fix_info.get("versions") or []

            vulns_by_sbom.setdefault(row.sbom_id, []).append(
                {
                    "cve_id": row.cve_id,
                    "severity": row.severity,
                    "cvss_score": row.cvss_score,
                    "summary": row.summary,
                    "service_name": svc_name,
                    "dependency_purl": row.dependency_purl,
                    "dependency_name": _dep_name(row.name, row.version, row.dependency_purl),
                }
            )
            if row.cve_id not in seen and row.sbom_id in latest_sbom_ids:
                seen.add(row.cve_id)
                project_vulns.append(
                    {
                        "cve_id": row.cve_id,
                        "severity": row.severity,
                        "cvss_score": row.cvss_score,
                        "summary": row.summary,
                        "service_name": svc_name,
                        "dependency_purl": row.dependency_purl,
                        "dependency_name": _dep_name(row.name, row.version, row.dependency_purl),
                        "cvss_vector": cvss_vec,
                        "published": row.published_at.strftime("%Y-%m-%d")
                        if row.published_at
                        else "",
                        "urls": urls,
                        "fix_versions": fix_versions,
                    }
                )

    # Count fixed vulnerabilities per SBOM (all SBOMs, not just latest)
    all_sbom_ids = [s.id for s in sboms]
    if all_sbom_ids:
        fixed_rows = await db.execute(
            select(
                SBOMVulnerability.sbom_id,
                func.count(SBOMVulnerability.vulnerability_id),
            )
            .where(
                SBOMVulnerability.sbom_id.in_(all_sbom_ids),
                SBOMVulnerability.status == "fixed",
            )
            .group_by(SBOMVulnerability.sbom_id)
        )
        for s_id, cnt in fixed_rows:
            fixed_by_sbom[s_id] = cnt

    services_result = await db.execute(
        select(Service).where(Service.project_id == project_id).order_by(Service.name)
    )
    services = services_result.scalars().all()

    return templates.TemplateResponse(
        request,
        "projects/detail.html",
        {
            "project": project,
            "sboms": sboms,
            "svc_names": svc_names,
            "services": services,
            "active_service_id": service_id or "",
            "vulns_by_sbom": vulns_by_sbom,
            "fixed_by_sbom": fixed_by_sbom,
            "project_vulns": project_vulns,
        },
    )


@router.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
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
    if order == "asc":
        if sort == "severity":
            severity_case = case(
                (Vulnerability.severity == "CRITICAL", 0),
                (Vulnerability.severity == "HIGH", 1),
                (Vulnerability.severity == "MEDIUM", 2),
                (Vulnerability.severity == "LOW", 3),
                else_=99,
            )
            query = query.order_by(severity_case.asc(), Vulnerability.cvss_score.desc().nullslast())
        else:
            query = query.order_by(
                sort_col.asc().nullslast(), Vulnerability.cvss_score.desc().nullslast()
            )
    else:
        if sort == "severity":
            severity_case = case(
                (Vulnerability.severity == "CRITICAL", 0),
                (Vulnerability.severity == "HIGH", 1),
                (Vulnerability.severity == "MEDIUM", 2),
                (Vulnerability.severity == "LOW", 3),
                else_=99,
            )
            query = query.order_by(
                severity_case.desc(), Vulnerability.cvss_score.desc().nullslast()
            )
        else:
            query = query.order_by(
                sort_col.desc().nullslast(), Vulnerability.cvss_score.desc().nullslast()
            )

    result = await db.execute(query)
    vulns = result.scalars().all()

    project_map = {}
    service_map = {}
    if vulns:
        vuln_ids = [v.id for v in vulns]
        proj_rows = await db.execute(
            select(SBOMVulnerability.vulnerability_id, Project.name)
            .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
            .join(Project, SBOM.project_id == Project.id)
            .where(SBOMVulnerability.vulnerability_id.in_(vuln_ids))
        )
        for v_id, proj_name in proj_rows:
            project_map.setdefault(v_id, set()).add(proj_name)

        svc_rows = await db.execute(
            select(SBOMVulnerability.vulnerability_id, Service.name)
            .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
            .outerjoin(Service, SBOM.service_id == Service.id)
            .where(SBOMVulnerability.vulnerability_id.in_(vuln_ids))
        )
        service_map = {}
        for v_id, svc_name in svc_rows:
            if svc_name:
                service_map.setdefault(v_id, set()).add(svc_name)

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

    return templates.TemplateResponse(
        request,
        "vulnerabilities/list.html",
        {
            "vulnerabilities": vulns,
            "project_map": project_map,
            "service_map": service_map,
            "projects": projects,
            "services": services,
            "active_severity": severity or "",
            "active_project_id": project_id or "",
            "active_service_id": service_id or "",
            "active_sort": sort,
            "active_order": order,
        },
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: AsyncSession = Depends(get_db)):
    projects = (await db.execute(select(Project).order_by(Project.name))).scalars().all()
    alerts = (
        (await db.execute(select(AlertConfig).order_by(AlertConfig.created_at.desc())))
        .scalars()
        .all()
    )
    api_keys = await list_api_keys(db)
    project_names = {str(p.id): p.name for p in projects}
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "projects": projects,
            "alerts": alerts,
            "api_keys": api_keys,
            "project_names": project_names,
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

    result = await db.execute(query)
    rows = result.all()

    sboms = []
    sbom_ids = []
    for sbom, proj_name, svc_name in rows:
        sboms.append((sbom, proj_name, svc_name))
        sbom_ids.append(sbom.id)

    vuln_counts = {}
    if sbom_ids:
        vc_rows = await db.execute(
            select(
                SBOMVulnerability.sbom_id,
                func.count(SBOMVulnerability.vulnerability_id),
            )
            .where(
                SBOMVulnerability.sbom_id.in_(sbom_ids),
                SBOMVulnerability.status == "open",
            )
            .group_by(SBOMVulnerability.sbom_id)
        )
        for s_id, cnt in vc_rows:
            vuln_counts[s_id] = cnt

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

    return templates.TemplateResponse(
        request,
        "sboms/list.html",
        {
            "sboms": sboms,
            "vuln_counts": vuln_counts,
            "projects": projects,
            "services": services,
            "active_sort": sort,
            "active_order": order,
            "active_project_id": project_id or "",
            "active_service_id": service_id or "",
        },
    )
