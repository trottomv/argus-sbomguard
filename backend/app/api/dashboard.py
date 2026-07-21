from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import AlertConfig
from app.models.project import Project
from app.models.sbom import SBOM
from app.models.vulnerability import SBOMVulnerability, Vulnerability, VulnerabilitySnapshot

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

router = APIRouter(tags=["dashboard"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    project_count = (await db.execute(select(func.count(Project.id)))).scalar() or 0
    sbom_count = (await db.execute(select(func.count(SBOM.id)))).scalar() or 0

    vuln_subq = (
        select(Vulnerability.id, Vulnerability.severity)
        .join(SBOMVulnerability)
        .where(SBOMVulnerability.status == "open")
        .distinct(Vulnerability.id)
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

    recent_result = await db.execute(
        select(SBOM, Project.name)
        .join(Project, SBOM.project_id == Project.id)
        .order_by(SBOM.created_at.desc())
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
            "recent_sboms": recent_sboms,
            "chart_labels": chart_labels,
            "chart_critical": chart_critical,
            "chart_high": chart_high,
            "chart_medium": chart_medium,
            "chart_low": chart_low,
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
    request: Request, project_id: str, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return RedirectResponse(url="/projects")

    sboms_result = await db.execute(
        select(SBOM).where(SBOM.project_id == project_id).order_by(SBOM.created_at.desc())
    )
    sboms = sboms_result.scalars().all()

    sbom_ids = [s.id for s in sboms]
    vulns_by_sbom = {}
    project_vulns = []
    if sbom_ids:
        vuln_rows = await db.execute(
            select(
                SBOMVulnerability.sbom_id,
                Vulnerability.cve_id,
                Vulnerability.severity,
                Vulnerability.cvss_score,
                Vulnerability.summary,
            )
            .join(Vulnerability, SBOMVulnerability.vulnerability_id == Vulnerability.id)
            .where(
                SBOMVulnerability.sbom_id.in_(sbom_ids),
                SBOMVulnerability.status == "open",
            )
            .order_by(Vulnerability.cvss_score.desc().nullslast())
        )
        seen = set()
        for row in vuln_rows:
            vulns_by_sbom.setdefault(row.sbom_id, []).append(
                {
                    "cve_id": row.cve_id,
                    "severity": row.severity,
                    "cvss_score": row.cvss_score,
                    "summary": row.summary,
                }
            )
            if row.cve_id not in seen:
                seen.add(row.cve_id)
                project_vulns.append(
                    {
                        "cve_id": row.cve_id,
                        "severity": row.severity,
                        "cvss_score": row.cvss_score,
                        "summary": row.summary,
                    }
                )

    return templates.TemplateResponse(
        request,
        "projects/detail.html",
        {
            "project": project,
            "sboms": sboms,
            "vulns_by_sbom": vulns_by_sbom,
            "project_vulns": project_vulns,
        },
    )


@router.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    severity: str = Query(None),
    project_id: str = Query(None),
    sort: str = Query("cvss_score"),
    order: str = Query("desc"),
):
    subq = (
        select(Vulnerability.id).join(SBOMVulnerability).where(SBOMVulnerability.status == "open")
    )
    if severity and severity != "":
        subq = subq.where(Vulnerability.severity.ilike(severity))
    if project_id and project_id != "":
        subq = subq.join(SBOM, SBOMVulnerability.sbom_id == SBOM.id).where(
            SBOM.project_id == project_id
        )
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

    projects = (await db.execute(select(Project).order_by(Project.name))).scalars().all()

    return templates.TemplateResponse(
        request,
        "vulnerabilities/list.html",
        {
            "vulnerabilities": vulns,
            "project_map": project_map,
            "projects": projects,
            "active_severity": severity or "",
            "active_project_id": project_id or "",
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
    return templates.TemplateResponse(
        request,
        "settings.html",
        {"projects": projects, "alerts": alerts},
    )


@router.get("/sboms", response_class=HTMLResponse)
async def sboms_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    sort: str = Query("created_at"),
    order: str = Query("desc"),
    project_id: str = Query(None),
):
    query = select(SBOM, Project.name).join(Project, SBOM.project_id == Project.id)
    if project_id and project_id != "":
        query = query.where(SBOM.project_id == project_id)

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
    for sbom, proj_name in rows:
        sboms.append((sbom, proj_name))
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

    return templates.TemplateResponse(
        request,
        "sboms/list.html",
        {
            "sboms": sboms,
            "vuln_counts": vuln_counts,
            "projects": projects,
            "active_sort": sort,
            "active_order": order,
            "active_project_id": project_id or "",
        },
    )
