import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.project import Project
from app.models.sbom import SBOM

router = APIRouter(prefix="/api/v1/projects", tags=["projects"])


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None
    repo_url: str | None = None
    platform: str | None = None


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: str | None
    repo_url: str | None
    platform: str | None
    created_at: str
    sbom_count: int = 0

    model_config = {"from_attributes": True}


@router.get("")
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.created_at.desc()))
    projects = result.scalars().all()
    return {"projects": [_project_to_dict(p) for p in projects]}


@router.post("", status_code=201)
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
    await db.flush()
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
async def project_history(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(SBOM).where(SBOM.project_id == project_id).order_by(SBOM.created_at.desc())
    )
    sboms = result.scalars().all()
    return {
        "sboms": [
            {
                "id": str(s.id),
                "version": s.version,
                "format": s.format,
                "dependency_count": s.dependency_count,
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in sboms
        ]
    }


def _project_to_dict(p: Project) -> dict:
    return {
        "id": str(p.id),
        "name": p.name,
        "description": p.description,
        "repo_url": p.repo_url,
        "platform": p.platform,
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }
