import json
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.project import Project
from app.models.sbom import SBOM, Dependency
from app.models.vulnerability import SBOMVulnerability, Vulnerability
from app.services.sbom_parser import store_sbom
from app.services.tasks import scan_sbom

router = APIRouter(prefix="/api/v1/sboms", tags=["sboms"])


@router.post("/upload", status_code=201)
async def upload_sbom(
    project_id: str = Form(...),
    version: str = Form(None),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    project_uuid = uuid.UUID(project_id)
    result = await db.execute(select(Project).where(Project.id == project_uuid))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    content = await file.read()
    raw = json.loads(content)

    sbom = await store_sbom(db, project_uuid, raw, version)
    await db.commit()

    scan_sbom.delay(str(sbom.id))

    return {
        "id": str(sbom.id),
        "format": sbom.format,
        "dependency_count": sbom.dependency_count,
        "sha256": sbom.sha256,
    }


@router.get("/{sbom_id}")
async def get_sbom(sbom_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SBOM).where(SBOM.id == sbom_id))
    sbom = result.scalar_one_or_none()
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    deps_result = await db.execute(select(Dependency).where(Dependency.sbom_id == sbom_id))
    deps = deps_result.scalars().all()

    vuln_result = await db.execute(
        select(Vulnerability).join(SBOMVulnerability).where(SBOMVulnerability.sbom_id == sbom_id)
    )
    vulns = vuln_result.scalars().all()

    return {
        "id": str(sbom.id),
        "project_id": str(sbom.project_id),
        "version": sbom.version,
        "format": sbom.format,
        "sha256": sbom.sha256,
        "dependency_count": sbom.dependency_count,
        "created_at": sbom.created_at.isoformat() if sbom.created_at else None,
        "dependencies": [
            {
                "name": d.name,
                "version": d.version,
                "purl": d.purl,
                "type": d.dep_type,
                "license": d.license,
                "is_direct": d.is_direct,
            }
            for d in deps
        ],
        "vulnerabilities": [
            {
                "id": str(v.id),
                "cve_id": v.cve_id,
                "severity": v.severity,
                "summary": v.summary,
            }
            for v in vulns
        ],
    }


@router.get("/{sbom_id}/diff/{other_id}")
async def diff_sboms(
    sbom_id: uuid.UUID,
    other_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Dependency).where(Dependency.sbom_id == sbom_id))
    deps_a = {(d.name, d.version) for d in result.scalars().all()}

    result = await db.execute(select(Dependency).where(Dependency.sbom_id == other_id))
    deps_b = {(d.name, d.version) for d in result.scalars().all()}

    added = [{"name": n, "version": v} for n, v in deps_b - deps_a]
    removed = [{"name": n, "version": v} for n, v in deps_a - deps_b]
    changed = []

    names_a = {n: v for n, v in deps_a}
    names_b = {n: v for n, v in deps_b}
    common = set(names_a.keys()) & set(names_b.keys())
    for name in common:
        if names_a[name] != names_b[name]:
            changed.append(
                {
                    "name": name,
                    "from_version": names_a[name],
                    "to_version": names_b[name],
                }
            )

    return {"added": added, "removed": removed, "changed": changed}


@router.delete("/{sbom_id}", status_code=204)
async def delete_sbom(sbom_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SBOM).where(SBOM.id == sbom_id))
    sbom = result.scalar_one_or_none()
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")
    await db.delete(sbom)
    await db.commit()
