import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from middleware.api_key import api_key_required
from models.project import Project
from models.sbom import SBOM
from models.vulnerability import VulnerabilitySnapshot
from services.pagination import PROJECT_PER_PAGE, PROJECT_SBOM_HISTORY_PER_PAGE, Page, paginate

router = APIRouter(
    prefix="/api/v1/projects", tags=["projects"], dependencies=[Depends(api_key_required)]
)


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None
    repo_url: str | None = None
    platform: str | None = None


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    repo_url: str | None = None
    platform: str | None = None


class ProjectResponse(BaseModel):
    id: str
    slug: str
    name: str
    description: str | None
    repo_url: str | None
    platform: str | None
    created_at: str
    sbom_count: int = 0

    model_config = {"from_attributes": True}


@router.get("")
async def list_projects(
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(PROJECT_PER_PAGE, ge=1, le=200),
):
    query = select(Project).order_by(Project.created_at.desc())
    pg: Page = await paginate(db, query, page=page, per_page=per_page)
    return {
        "items": [_project_to_dict(p) for p in pg.items],
        "total": pg.total,
        "page": pg.page,
        "per_page": pg.per_page,
        "total_pages": pg.total_pages,
    }


@router.post("", status_code=201)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    _validate_sluggable_name(data.name)

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
    return _project_to_dict(project)


@router.get("/{project_id}")
async def get_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return _project_to_dict(project)


@router.get("/{project_id}/history")
async def project_history(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(PROJECT_SBOM_HISTORY_PER_PAGE, ge=1, le=200),
):
    query = select(SBOM).where(SBOM.project_id == project_id).order_by(SBOM.created_at.desc())
    pg: Page = await paginate(db, query, page=page, per_page=per_page)
    return {
        "items": [
            {
                "id": str(s.id),
                "version": s.version,
                "format": s.format,
                "dependency_count": s.dependency_count,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in pg.items
        ],
        "total": pg.total,
        "page": pg.page,
        "per_page": pg.per_page,
        "total_pages": pg.total_pages,
    }


@router.delete("/{project_id}", status_code=204)
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


@router.patch("/{project_id}")
async def update_project(
    project_id: uuid.UUID, data: ProjectUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if data.name is not None:
        _validate_sluggable_name(data.name)
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
    return _project_to_dict(project)


def _validate_sluggable_name(name: str) -> None:
    """Reject names that would slugify to an empty string (no alphanumeric)."""
    if not any(c.isalnum() for c in name):
        raise HTTPException(
            status_code=422,
            detail="Project name must contain at least one alphanumeric character",
        )


def _is_slug_conflict(exc: IntegrityError) -> bool:
    """Return True when the failing UNIQUE constraint is the slug index."""
    constraint = getattr(exc.orig, "constraint_name", None)
    if constraint:
        return "slug" in str(constraint)
    return "slug" in str(exc.orig)


def _project_to_dict(p: Project) -> dict:
    return {
        "id": str(p.id),
        "slug": p.slug,
        "name": p.name,
        "description": p.description,
        "repo_url": p.repo_url,
        "platform": p.platform,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }
