from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import AlertConfig
from app.models.project import Project
from app.models.sbom import SBOM
from app.models.vulnerability import SBOMVulnerability, Vulnerability

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

    recent_result = await db.execute(
        select(SBOM).order_by(SBOM.created_at.desc()).limit(5)
    )
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
        select(SBOM)
        .where(SBOM.project_id == project_id)
        .order_by(SBOM.created_at.desc())
    )
    sboms = sboms_result.scalars().all()

    return templates.TemplateResponse(
        request,
        "projects/detail.html",
        {"project": project, "sboms": sboms},
    )


@router.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities_page(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Vulnerability)
        .join(SBOMVulnerability)
        .where(SBOMVulnerability.status == "open")
        .distinct()
        .order_by(Vulnerability.cvss_score.desc().nullslast())
    )
    vulns = result.scalars().all()
    return templates.TemplateResponse(
        request,
        "vulnerabilities/list.html",
        {"vulnerabilities": vulns},
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: AsyncSession = Depends(get_db)):
    projects = (await db.execute(select(Project).order_by(Project.name))).scalars().all()
    alerts = (await db.execute(select(AlertConfig).order_by(AlertConfig.created_at.desc()))).scalars().all()
    return templates.TemplateResponse(
        request,
        "settings.html",
        {"projects": projects, "alerts": alerts},
    )
