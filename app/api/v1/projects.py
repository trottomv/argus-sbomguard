import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from api.constants import API_V1_PREFIX
from api.v1.schemas import (
    BAD_REQUEST_RESPONSE,
    CONFLICT_RESPONSE,
    NOT_FOUND_RESPONSE,
    UNAUTHORIZED_RESPONSE,
    PageResponse,
    ProjectCreate,
    ProjectResponse,
    ProjectSBOMHistoryItem,
    ProjectUpdate,
)
from database import get_db
from middleware.api_key import api_key_required
from models.project import Project
from models.sbom import SBOM
from models.vulnerability import VulnerabilitySnapshot
from services.pagination import PROJECT_PER_PAGE, PROJECT_SBOM_HISTORY_PER_PAGE, Page, paginate

router = APIRouter(
    prefix=f"{API_V1_PREFIX}/projects",
    tags=["projects"],
    dependencies=[Depends(api_key_required)],
)


@router.get("", response_model=PageResponse[ProjectResponse], responses={**UNAUTHORIZED_RESPONSE})
async def list_projects(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(PROJECT_PER_PAGE, ge=1, le=200),
):
    query = select(Project).order_by(Project.created_at.desc())
    pg: Page = await paginate(db, query, page=page, per_page=per_page)
    return PageResponse[ProjectResponse](
        items=[ProjectResponse.model_validate(project) for project in pg.items],
        total=pg.total,
        page=pg.page,
        per_page=pg.per_page,
        total_pages=pg.total_pages,
        has_more=pg.has_more,
    )


@router.post(
    "",
    status_code=201,
    response_model=ProjectResponse,
    responses={**UNAUTHORIZED_RESPONSE, **CONFLICT_RESPONSE, **BAD_REQUEST_RESPONSE},
)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(Project).where(Project.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Project already exists")

    project = Project(
        name=data.name,
        description=data.description,
        repo_url=data.repo_url,
        platform=data.platform,
    )
    db.add(project)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "Project slug already in use"
                if _is_slug_conflict(exc)
                else "Project name already exists"
            ),
        ) from None
    await db.refresh(project)
    return ProjectResponse.model_validate(project)


@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
    responses={**UNAUTHORIZED_RESPONSE, **NOT_FOUND_RESPONSE},
)
async def get_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectResponse.model_validate(project)


@router.get(
    "/{project_id}/history",
    response_model=PageResponse[ProjectSBOMHistoryItem],
    responses={**UNAUTHORIZED_RESPONSE, **NOT_FOUND_RESPONSE},
)
async def project_history(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(PROJECT_SBOM_HISTORY_PER_PAGE, ge=1, le=200),
):
    project = await db.execute(select(Project).where(Project.id == project_id))
    if not project.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    query = select(SBOM).where(SBOM.project_id == project_id).order_by(SBOM.created_at.desc())
    pg: Page = await paginate(db, query, page=page, per_page=per_page)
    return PageResponse[ProjectSBOMHistoryItem](
        items=[ProjectSBOMHistoryItem.model_validate(sbom) for sbom in pg.items],
        total=pg.total,
        page=pg.page,
        per_page=pg.per_page,
        total_pages=pg.total_pages,
        has_more=pg.has_more,
    )


@router.delete(
    "/{project_id}",
    status_code=204,
    responses={**UNAUTHORIZED_RESPONSE, **NOT_FOUND_RESPONSE},
)
async def delete_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    await db.execute(
        sa_delete(VulnerabilitySnapshot).where(VulnerabilitySnapshot.project_id == project_id)
    )
    await db.delete(project)
    await db.commit()


@router.patch(
    "/{project_id}",
    response_model=ProjectResponse,
    responses={
        **UNAUTHORIZED_RESPONSE,
        **NOT_FOUND_RESPONSE,
        **CONFLICT_RESPONSE,
        **BAD_REQUEST_RESPONSE,
    },
)
async def update_project(
    project_id: uuid.UUID, data: ProjectUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if data.name is not None:
        existing = await db.execute(
            select(Project).where(Project.name == data.name, Project.id != project_id)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Project name already exists")
        project.name = data.name
    if data.description is not None:
        project.description = data.description
    if data.repo_url is not None:
        project.repo_url = data.repo_url
    if data.platform is not None:
        project.platform = data.platform

    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail=(
                "Project slug already in use"
                if _is_slug_conflict(exc)
                else "Project name already exists"
            ),
        ) from None
    await db.refresh(project)
    return ProjectResponse.model_validate(project)


def _is_slug_conflict(exc: IntegrityError) -> bool:
    """Return True when the failing UNIQUE constraint is the slug index."""
    constraint = getattr(exc.orig, "constraint_name", None)
    if constraint:
        return "slug" in str(constraint)
    return "slug" in str(exc.orig)
