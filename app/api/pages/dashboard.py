from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.project import Project
from models.sbom import SBOM
from models.service import Service
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)
from services.tasks import snapshot_metrics
from templating import templates

router = APIRouter(tags=["dashboard"], include_in_schema=False)


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

    ctx = {
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
    }
    return templates.TemplateResponse(request, "dashboard.html", ctx)


@router.post("/refresh-snapshots", status_code=202)
async def refresh_snapshots():
    snapshot_metrics.delay()
    return Response(status_code=202)
