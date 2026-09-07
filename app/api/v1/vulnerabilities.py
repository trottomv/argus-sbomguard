import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.constants import API_V1_PREFIX
from api.v1.schemas import (
    BAD_REQUEST_RESPONSE,
    CONFLICT_RESPONSE,
    NOT_FOUND_RESPONSE,
    UNAUTHORIZED_RESPONSE,
    PageResponse,
    RiskAcceptanceCreate,
    RiskAcceptanceResponse,
    VulnerabilityResponse,
    VulnerabilitySummaryResponse,
)
from database import get_db
from middleware.api_key import api_key_required
from models.acceptance import RiskAcceptance
from models.project import Project
from models.sbom import SBOM
from models.service import Service
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from services.acceptance import covered_by_acceptance
from services.pagination import VULN_PER_PAGE, Page, paginate
from services.vulnerability_queries import apply_vuln_ordering, build_vuln_subquery

router = APIRouter(
    prefix=f"{API_V1_PREFIX}/vulnerabilities",
    tags=["vulnerabilities"],
    dependencies=[Depends(api_key_required)],
)


@router.get(
    "/active",
    response_model=PageResponse[VulnerabilityResponse],
    responses={**UNAUTHORIZED_RESPONSE},
)
async def active_vulnerabilities(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(VULN_PER_PAGE, ge=1, le=200),
    severity: str = Query(None),
    project_id: uuid.UUID | None = Query(None),
    service_id: uuid.UUID | None = Query(None),
    cve_id: str = Query(None),
    sort: str = Query("cvss_score"),
    order: str = Query("desc"),
):
    query = select(Vulnerability).where(
        Vulnerability.id.in_(build_vuln_subquery(severity, project_id, service_id, cve_id))
    )
    query = apply_vuln_ordering(query, sort, order)

    pg: Page = await paginate(db, query, page=page, per_page=per_page)

    vuln_ids = [vuln.id for vuln in pg.items]
    project_map: dict[str, set[str]] = {}
    service_map: dict[str, set[str]] = {}
    if vuln_ids:
        proj_rows = (
            await db.execute(
                select(SBOMVulnerability.vulnerability_id, SBOM.project_id.label("name"))
                .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
                .where(
                    SBOMVulnerability.status == VulnerabilityStatus.OPEN,
                    SBOMVulnerability.vulnerability_id.in_(vuln_ids),
                )
                .where(~covered_by_acceptance(SBOMVulnerability, SBOM))
            )
        ).all()
        proj_ids = {row[1] for row in proj_rows}
        proj_lines = {}
        if proj_ids:
            from models.project import Project

            proj_lines_rows = await db.execute(
                select(Project.id, Project.name).where(Project.id.in_(proj_ids))
            )
            proj_lines = {
                str(project_id): project_name for project_id, project_name in proj_lines_rows
            }

        for vuln_id, project_id in proj_rows:
            project_name = proj_lines.get(str(project_id), "")
            if project_name:
                project_map.setdefault(vuln_id, set()).add(project_name)

        svc_rows = await db.execute(
            select(SBOMVulnerability.vulnerability_id, Service.name)
            .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
            .outerjoin(Service, SBOM.service_id == Service.id)
            .where(
                SBOMVulnerability.status == VulnerabilityStatus.OPEN,
                SBOMVulnerability.vulnerability_id.in_(vuln_ids),
            )
            .where(~covered_by_acceptance(SBOMVulnerability, SBOM))
        )
        for vuln_id, service_name in svc_rows:
            if service_name:
                service_map.setdefault(vuln_id, set()).add(service_name)

    return PageResponse[VulnerabilityResponse](
        items=[
            VulnerabilityResponse(
                id=vuln.id,
                cve_id=vuln.cve_id,
                severity=vuln.severity,
                cvss_score=vuln.cvss_score,
                epss_score=vuln.epss_score,
                epss_percentile=vuln.epss_percentile,
                summary=vuln.summary,
                source=vuln.source,
                published_at=vuln.published_at,
                projects=sorted(project_map.get(vuln.id, [])),
                services=sorted(service_map.get(vuln.id, [])),
            )
            for vuln in pg.items
        ],
        total=pg.total,
        page=pg.page,
        per_page=pg.per_page,
        total_pages=pg.total_pages,
        has_more=pg.has_more,
    )


@router.get(
    "/summary",
    response_model=VulnerabilitySummaryResponse,
    responses={**UNAUTHORIZED_RESPONSE},
)
async def vulnerability_summary(db: AsyncSession = Depends(get_db)):
    vuln_subq = (
        select(Vulnerability.id, Vulnerability.severity)
        .join(SBOMVulnerability)
        .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
        .where(SBOMVulnerability.status == VulnerabilityStatus.OPEN)
        .where(~covered_by_acceptance(SBOMVulnerability, SBOM))
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

    counts = {
        "critical": row.critical or 0,
        "high": row.high or 0,
        "medium": row.medium or 0,
        "low": row.low or 0,
        "unknown": 0,
    }

    affected = await db.execute(
        select(func.count()).select_from(
            select(SBOM.project_id.distinct())
            .join(SBOMVulnerability, SBOMVulnerability.sbom_id == SBOM.id)
            .where(SBOMVulnerability.status == VulnerabilityStatus.OPEN)
            .where(~covered_by_acceptance(SBOMVulnerability, SBOM))
            .subquery()
        )
    )

    return VulnerabilitySummaryResponse(
        counts=counts,
        total=sum(counts.values()),
        affected_projects=affected.scalar() or 0,
    )


@router.get(
    "/acceptances",
    response_model=PageResponse[RiskAcceptanceResponse],
    responses={**UNAUTHORIZED_RESPONSE},
)
async def list_risk_acceptances(
    db: AsyncSession = Depends(get_db),
    project_id: uuid.UUID | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
):
    query = select(RiskAcceptance).order_by(RiskAcceptance.created_at.desc())
    if project_id is not None:
        query = query.where(RiskAcceptance.project_id == project_id)
    pg: Page = await paginate(db, query, page=page, per_page=per_page)
    return PageResponse[RiskAcceptanceResponse](
        items=[RiskAcceptanceResponse.model_validate(ra) for ra in pg.items],
        total=pg.total,
        page=pg.page,
        per_page=pg.per_page,
        total_pages=pg.total_pages,
        has_more=pg.has_more,
    )


@router.post(
    "/acceptances",
    status_code=201,
    response_model=RiskAcceptanceResponse,
    responses={
        **UNAUTHORIZED_RESPONSE,
        **NOT_FOUND_RESPONSE,
        **BAD_REQUEST_RESPONSE,
        **CONFLICT_RESPONSE,
    },
)
async def create_risk_acceptance(data: RiskAcceptanceCreate, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, data.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    vuln = await db.get(Vulnerability, data.vulnerability_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    if data.service_id is not None:
        service = await db.get(Service, data.service_id)
        if not service or service.project_id != data.project_id:
            raise HTTPException(status_code=400, detail="Service does not belong to the project")

    # #2 — only accept a vulnerability that is actually open in the requested
    # scope; otherwise the row is a silent no-op (or a "pre-acceptance" of a
    # CVE that has never been seen here).
    open_link = (
        select(SBOMVulnerability.sbom_id)
        .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
        .where(
            SBOMVulnerability.vulnerability_id == data.vulnerability_id,
            SBOMVulnerability.status == VulnerabilityStatus.OPEN,
            SBOM.project_id == data.project_id,
        )
    )
    if data.service_id is not None:
        open_link = open_link.where(SBOM.service_id == data.service_id)
    if not (await db.execute(open_link.limit(1))).first():
        raise HTTPException(
            status_code=400, detail="Vulnerability is not open in the requested scope"
        )

    # #4 — at most one acceptance per (project, vulnerability): a project-level
    # row subsumes every service row, so creating one underneath (or on top of)
    # an existing, broader decision is rejected instead of stored redundantly.
    existing = (
        (
            await db.execute(
                select(RiskAcceptance).where(
                    RiskAcceptance.project_id == data.project_id,
                    RiskAcceptance.vulnerability_id == data.vulnerability_id,
                )
            )
        )
        .scalars()
        .all()
    )
    if data.service_id is None:
        if existing:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Vulnerability already accepted for this project; "
                    "revert the narrower acceptances first"
                ),
            )
    else:
        if any(row.service_id is None for row in existing):
            raise HTTPException(
                status_code=409, detail="Vulnerability already accepted at project scope"
            )
        if any(row.service_id == data.service_id for row in existing):
            raise HTTPException(
                status_code=409, detail="Vulnerability already accepted in this service"
            )

    acceptance = RiskAcceptance(
        project_id=data.project_id,
        service_id=data.service_id,
        vulnerability_id=data.vulnerability_id,
        reason=data.reason,
    )
    db.add(acceptance)
    try:
        await db.flush()
    except IntegrityError:
        # A concurrent request created the same (project, service, vuln) row.
        await db.rollback()
        raise HTTPException(
            status_code=409, detail="Vulnerability already accepted in this scope"
        ) from None
    return RiskAcceptanceResponse.model_validate(acceptance)


@router.delete(
    "/acceptances/{acceptance_id}",
    status_code=204,
    responses={**UNAUTHORIZED_RESPONSE, **NOT_FOUND_RESPONSE},
)
async def delete_risk_acceptance(acceptance_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RiskAcceptance).where(RiskAcceptance.id == acceptance_id))
    acceptance = result.scalar_one_or_none()
    if not acceptance:
        raise HTTPException(status_code=404, detail="Risk acceptance not found")
    await db.delete(acceptance)
    await db.flush()
