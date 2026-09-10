from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.pages.common import dep_name
from database import get_db
from models.acceptance import RiskAcceptance
from models.project import Project
from models.sbom import SBOM, Dependency
from models.service import Service
from models.vulnerability import SBOMVulnerability, Vulnerability, VulnerabilityStatus
from services.acceptance import covered_by_acceptance
from services.pagination import VULN_PER_PAGE, Page, paginate
from services.vulnerability_queries import apply_vuln_ordering, build_vuln_subquery
from templating import templates

router = APIRouter(tags=["vulnerabilities"], include_in_schema=False)


async def _filter_dropdowns(
    db: AsyncSession, project_id: str | None, page: int
) -> tuple[list, list]:
    """Project/service options for the filter selects, only on the first page."""
    if page != 1:
        return [], []
    projects = (await db.execute(select(Project).order_by(Project.name))).scalars().all()
    service_q = (
        select(Service).where(Service.project_id == project_id)
        if project_id and project_id != ""
        else select(Service)
    )
    services = (await db.execute(service_q.order_by(Service.name))).scalars().all()
    return projects, services


def _accepted_item(acceptance, vuln, project_name, service_name) -> dict:
    extra = vuln.extra_data or {}
    cvss_list = extra.get("cvss") or []
    return {
        "acceptance_id": str(acceptance.id),
        "vulnerability_id": str(vuln.id),
        "cve_id": vuln.cve_id,
        "severity": vuln.severity,
        "cvss_score": vuln.cvss_score,
        "epss_score": vuln.epss_score,
        "epss_percentile": vuln.epss_percentile,
        "summary": vuln.summary,
        "project_id": str(acceptance.project_id),
        "project_name": project_name,
        "service_id": str(acceptance.service_id) if acceptance.service_id else "",
        "service_name": service_name or "",
        "reason": acceptance.reason,
        "created_at": acceptance.created_at,
        "cvss_vector": cvss_list[0].get("vector") if cvss_list else "",
        "urls": extra.get("urls") or [],
    }


async def _accepted_page(
    db: AsyncSession,
    *,
    severity: str | None,
    cve_id: str | None,
    project_id: str | None,
    service_id: str | None,
    page: int,
    per_page: int,
) -> tuple[list, Page]:
    query = (
        select(RiskAcceptance, Vulnerability, Project.name, Service.name)
        .join(Vulnerability, RiskAcceptance.vulnerability_id == Vulnerability.id)
        .join(Project, RiskAcceptance.project_id == Project.id)
        .outerjoin(Service, RiskAcceptance.service_id == Service.id)
    )
    if severity and severity != "":
        query = query.where(Vulnerability.severity.ilike(severity.replace("\x00", "")))
    if cve_id and cve_id != "":
        query = query.where(Vulnerability.cve_id.ilike(f"%{cve_id.replace('\x00', '')}%"))
    if project_id and project_id != "":
        query = query.where(RiskAcceptance.project_id == project_id)
    if service_id and service_id != "":
        query = query.where(RiskAcceptance.service_id == service_id)
    query = query.order_by(RiskAcceptance.created_at.desc())

    pg: Page = await paginate(db, query, page=page, per_page=per_page, scalar=False)
    return [_accepted_item(*row) for row in pg.items], pg


async def _active_maps(db: AsyncSession, vulns: list) -> tuple[dict, dict, dict, dict]:
    """Per-vulnerability project/service labels, valid accept scopes and libraries."""
    project_map: dict = {}
    service_map: dict = {}
    scope_map: dict = {}
    dep_map: dict = {}
    if not vulns:
        return project_map, service_map, scope_map, dep_map

    vuln_ids = [vuln.id for vuln in vulns]
    scope_rows = await db.execute(
        select(
            SBOMVulnerability.vulnerability_id,
            SBOM.project_id,
            Project.name,
            SBOM.service_id,
            Service.name,
        )
        .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
        .join(Project, SBOM.project_id == Project.id)
        .outerjoin(Service, SBOM.service_id == Service.id)
        .where(
            SBOMVulnerability.status == VulnerabilityStatus.OPEN,
            SBOMVulnerability.vulnerability_id.in_(vuln_ids),
        )
        .where(~covered_by_acceptance(SBOMVulnerability, SBOM))
    )
    for vuln_id, proj_id, proj_name, svc_id, svc_name in scope_rows:
        project_map.setdefault(vuln_id, set()).add(proj_name)
        if svc_name:
            service_map.setdefault(vuln_id, set()).add(svc_name)
        bucket = scope_map.setdefault(vuln_id, {})
        key = str(svc_id) if svc_id else ""
        bucket[key] = {
            "project_id": str(proj_id),
            "project_name": proj_name,
            "service_id": str(svc_id) if svc_id else "",
            "service_name": svc_name or "",
        }
    scope_map = {
        vid: sorted(bucket.values(), key=lambda s: (s["project_name"], s["service_name"]))
        for vid, bucket in scope_map.items()
    }

    dep_rows = await db.execute(
        select(
            SBOMVulnerability.vulnerability_id,
            Dependency.name,
            Dependency.version,
            SBOMVulnerability.dependency_purl,
        )
        .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
        .outerjoin(
            Dependency,
            (SBOMVulnerability.sbom_id == Dependency.sbom_id)
            & (SBOMVulnerability.dependency_purl == Dependency.purl),
        )
        .where(
            SBOMVulnerability.vulnerability_id.in_(vuln_ids),
            SBOMVulnerability.status == VulnerabilityStatus.OPEN,
        )
        .where(~covered_by_acceptance(SBOMVulnerability, SBOM))
    )
    for vuln_id, dep_nm, dep_version, dep_purl in dep_rows:
        dep_map.setdefault(vuln_id, set()).add(dep_name(dep_nm, dep_version, dep_purl))
    dep_map = {vuln_id: sorted(names) for vuln_id, names in dep_map.items()}

    return project_map, service_map, scope_map, dep_map


@router.get("/vulnerabilities", response_class=HTMLResponse)
async def vulnerabilities_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    severity: str = Query(None),
    project_id: str = Query(None),
    service_id: str = Query(None),
    cve_id: str = Query(None),
    status: Literal["active", "accepted"] = Query("active"),
    sort: str = Query("cvss_score"),
    order: str = Query("desc"),
    page: int = Query(1, ge=1),
    per_page: int = Query(VULN_PER_PAGE, ge=1, le=200),
):
    projects, services = await _filter_dropdowns(db, project_id, page)

    load_more_url = (
        f"/vulnerabilities?severity={severity or ''}&project_id={project_id or ''}"
        f"&service_id={service_id or ''}&cve_id={cve_id or ''}&status={status}"
        f"&sort={sort}&order={order}&per_page={per_page}"
    )

    ctx = {
        "projects": projects,
        "services": services,
        "active_severity": severity or "",
        "active_project_id": project_id or "",
        "active_service_id": service_id or "",
        "active_cve": cve_id or "",
        "active_status": status,
        "active_sort": sort,
        "active_order": order,
        "per_page": per_page,
        "target": "vuln",
        "load_more_url": load_more_url,
    }

    if status == "accepted":
        items, pg = await _accepted_page(
            db,
            severity=severity,
            cve_id=cve_id,
            project_id=project_id,
            service_id=service_id,
            page=page,
            per_page=per_page,
        )
        ctx.update(
            {
                "items": items,
                "total": pg.total,
                "page": pg.page,
                "total_pages": pg.total_pages,
                "has_more": pg.has_more,
            }
        )
        if page > 1:
            return templates.TemplateResponse(
                request, "vulnerabilities/accepted_rows_partial.html", ctx
            )
        if request.headers.get("HX-Request"):
            return templates.TemplateResponse(request, "vulnerabilities/page.html", ctx)
        return templates.TemplateResponse(request, "vulnerabilities/list.html", ctx)

    query = select(Vulnerability).where(
        Vulnerability.id.in_(build_vuln_subquery(severity, project_id, service_id, cve_id))
    )
    query = apply_vuln_ordering(query, sort, order)

    pg = await paginate(db, query, page=page, per_page=per_page)
    project_map, service_map, scope_map, dep_map = await _active_maps(db, pg.items)

    ctx.update(
        {
            "items": pg.items,
            "project_map": project_map,
            "service_map": service_map,
            "scope_map": scope_map,
            "dep_map": dep_map,
            "total": pg.total,
            "page": pg.page,
            "total_pages": pg.total_pages,
            "has_more": pg.has_more,
        }
    )

    if page > 1:
        return templates.TemplateResponse(request, "vulnerabilities/rows_partial.html", ctx)

    if request.headers.get("HX-Request"):
        return templates.TemplateResponse(request, "vulnerabilities/page.html", ctx)

    return templates.TemplateResponse(request, "vulnerabilities/list.html", ctx)
