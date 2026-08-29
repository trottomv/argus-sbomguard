import json
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from api.constants import API_V1_PREFIX
from api.v1.schemas import (
    BAD_REQUEST_RESPONSE,
    NOT_FOUND_RESPONSE,
    UNAUTHORIZED_RESPONSE,
    DependencyResponse,
    DiffItemResponse,
    SBOMDetailResponse,
    SBOMDiffResponse,
    SBOMUploadResponse,
    VersionChangeResponse,
    VulnerabilityBriefResponse,
    _strip_nul_from_strings,
)
from database import get_db
from middleware.api_key import api_key_required
from models.project import Project
from models.sbom import SBOM, Dependency
from models.vulnerability import SBOMVulnerability, Vulnerability, VulnerabilityStatus
from services.sbom_parser import store_sbom
from services.tasks import scan_sbom

router = APIRouter(
    prefix=f"{API_V1_PREFIX}/sboms", tags=["sboms"], dependencies=[Depends(api_key_required)]
)


def _validation_error(loc: list[str | int], msg: str) -> RequestValidationError:
    """Build a 422 whose body matches the documented HTTPValidationError schema.

    HTTPException(422, detail="...") produces a string `detail`, which violates
    the OpenAPI HTTPValidationError (detail: array of ValidationError) and fails
    Schemathesis' response_schema_conformance. RequestValidationError is rendered
    by FastAPI with the standard array-shaped body; callers `raise` the result.
    """
    return RequestValidationError([{"loc": loc, "msg": msg, "type": "value_error"}])


@router.post(
    "/upload",
    status_code=201,
    response_model=SBOMUploadResponse,
    responses={**UNAUTHORIZED_RESPONSE, **NOT_FOUND_RESPONSE, **BAD_REQUEST_RESPONSE},
)
async def upload_sbom(
    project_id: str = Form(None),
    slug: str = Form(None),
    version: str = Form(None),
    service_name: str = Form(None),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    # PostgreSQL rejects NUL bytes in text and jsonb values, so strip them from
    # the multipart fields and the parsed SBOM before they reach a query or an
    # insert; a NUL in any of them would otherwise surface as a 500.
    project_id = _strip_nul_from_strings(project_id)
    slug = _strip_nul_from_strings(slug)
    version = _strip_nul_from_strings(version)
    service_name = _strip_nul_from_strings(service_name)

    if not project_id and not slug:
        raise _validation_error(["body", "project_id"], "project_id or slug is required")
    if project_id and slug:
        raise _validation_error(["body", "project_id"], "Provide only one of project_id or slug")

    if project_id:
        try:
            project_uuid = uuid.UUID(project_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="Project not found") from None
        result = await db.execute(select(Project).where(Project.id == project_uuid))
    else:
        result = await db.execute(select(Project).where(Project.slug == slug))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    content = await file.read()
    try:
        raw = json.loads(content)
    except json.JSONDecodeError:
        raise _validation_error(["body", "file"], "Invalid JSON") from None
    raw = _strip_nul_from_strings(raw)

    sbom = await store_sbom(db, project.id, raw, version, service_name=service_name or None)
    await db.commit()

    scan_sbom.delay(str(sbom.id))

    return SBOMUploadResponse(
        id=sbom.id,
        format=sbom.format,
        dependency_count=sbom.dependency_count,
        sha256=sbom.sha256,
    )


@router.get(
    "/{sbom_id}/download",
    responses={**UNAUTHORIZED_RESPONSE, **NOT_FOUND_RESPONSE},
)
async def download_sbom(sbom_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SBOM).where(SBOM.id == sbom_id))
    sbom = result.scalar_one_or_none()
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    content = json.dumps(sbom.raw_sbom, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=sbom-{sbom_id}.json"},
    )


@router.get(
    "/{sbom_id}",
    response_model=SBOMDetailResponse,
    responses={**UNAUTHORIZED_RESPONSE, **NOT_FOUND_RESPONSE},
)
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

    return SBOMDetailResponse(
        id=sbom.id,
        project_id=sbom.project_id,
        version=sbom.version,
        format=sbom.format,
        sha256=sbom.sha256,
        dependency_count=sbom.dependency_count,
        created_at=sbom.created_at,
        dependencies=[
            DependencyResponse(
                name=dep.name,
                version=dep.version,
                purl=dep.purl,
                type=dep.dep_type,
                license=dep.license,
                is_direct=dep.is_direct,
            )
            for dep in deps
        ],
        vulnerabilities=[
            VulnerabilityBriefResponse(
                id=vuln.id,
                cve_id=vuln.cve_id,
                severity=vuln.severity,
                summary=vuln.summary,
            )
            for vuln in vulns
        ],
    )


@router.get(
    "/{sbom_id}/diff/{other_id}",
    response_model=SBOMDiffResponse,
    responses={**UNAUTHORIZED_RESPONSE},
)
async def diff_sboms(
    sbom_id: uuid.UUID,
    other_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Dependency).where(Dependency.sbom_id == sbom_id))
    deps_a = {(dep.name, dep.version) for dep in result.scalars().all()}

    result = await db.execute(select(Dependency).where(Dependency.sbom_id == other_id))
    deps_b = {(dep.name, dep.version) for dep in result.scalars().all()}

    names_a = dict(deps_a)
    names_b = dict(deps_b)
    common = set(names_a.keys()) & set(names_b.keys())

    return SBOMDiffResponse(
        added=[DiffItemResponse(name=name, version=version) for name, version in deps_b - deps_a],
        removed=[DiffItemResponse(name=name, version=version) for name, version in deps_a - deps_b],
        changed=[
            VersionChangeResponse(
                name=name,
                from_version=names_a[name],
                to_version=names_b[name],
            )
            for name in common
            if names_a[name] != names_b[name]
        ],
    )


@router.delete(
    "/{sbom_id}",
    status_code=204,
    responses={**UNAUTHORIZED_RESPONSE, **NOT_FOUND_RESPONSE},
)
async def delete_sbom(sbom_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SBOM).where(SBOM.id == sbom_id))
    sbom = result.scalar_one_or_none()
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    # Find the latest remaining SBOM for this service, re-run reconcile
    latest_query = (
        select(SBOM)
        .where(
            SBOM.id != sbom_id,
            SBOM.service_id == sbom.service_id if sbom.service_id else SBOM.service_id.is_(None),
            SBOM.project_id == sbom.project_id,
        )
        .order_by(SBOM.uploaded_at.desc())
        .limit(1)
    )
    latest_result = await db.execute(latest_query)
    latest_sbom = latest_result.scalar_one_or_none()

    await db.delete(sbom)
    await db.flush()

    # Revert fixed vulns on older SBOMs back to open, then re-reconcile
    from services.vulnerability_scanner import reconcile_vulnerabilities

    older_ids = await db.execute(
        select(SBOM.id).where(
            SBOM.id != sbom_id,
            SBOM.service_id == sbom.service_id if sbom.service_id else SBOM.service_id.is_(None),
            SBOM.project_id == sbom.project_id,
        )
    )
    for (oid,) in older_ids:
        await db.execute(
            update(SBOMVulnerability)
            .where(
                SBOMVulnerability.sbom_id == oid,
                SBOMVulnerability.status == VulnerabilityStatus.FIXED,
            )
            .values(status=VulnerabilityStatus.OPEN, fixed_at=None)
        )

    if latest_sbom:
        await reconcile_vulnerabilities(db, latest_sbom)

    await db.commit()
