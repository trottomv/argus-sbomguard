from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import AlertConfig
from app.models.project import Project
from app.models.sbom import SBOM
from app.models.vulnerability import SBOMVulnerability, Vulnerability

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

    vuln_counts = await db.execute(
        select(
            func.count().filter(Vulnerability.severity.ilike("critical")).label("critical"),
            func.count().filter(Vulnerability.severity.ilike("high")).label("high"),
            func.count().filter(Vulnerability.severity.ilike("medium")).label("medium"),
            func.count().filter(Vulnerability.severity.ilike("low")).label("low"),
        )
        .select_from(Vulnerability)
        .join(SBOMVulnerability)
        .where(SBOMVulnerability.status == "open")
    )
    row = vuln_counts.one()

    recent_result = await db.execute(select(SBOM).order_by(SBOM.created_at.desc()).limit(5))
    recent_sboms = recent_result.scalars().all()

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
