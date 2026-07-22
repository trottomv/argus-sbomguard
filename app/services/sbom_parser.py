import hashlib
import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.sbom import SBOM, Dependency
from models.service import Service


def _extract_service_name(raw: dict) -> str | None:
    meta = raw.get("metadata") or {}
    component = meta.get("component") or {}
    name = component.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else None


def _extract_component_version(raw: dict) -> str | None:
    meta = raw.get("metadata") or {}
    component = meta.get("component") or {}
    ver = component.get("version")
    return ver.strip() if isinstance(ver, str) and ver.strip() else None


async def _get_or_create_service(db: AsyncSession, project_id: str, name: str) -> Service:
    result = await db.execute(
        select(Service).where(Service.project_id == project_id, Service.name == name)
    )
    service = result.scalar_one_or_none()
    if not service:
        service = Service(project_id=project_id, name=name)
        db.add(service)
        await db.flush()
    return service


def compute_sha256(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


async def parse_cyclonedx(raw: dict) -> list[dict]:
    deps = []
    components = raw.get("components", [])
    for comp in components:
        purl = comp.get("purl", "")
        deps.append(
            {
                "name": comp.get("name", ""),
                "version": comp.get("version", ""),
                "purl": purl,
                "dep_type": comp.get("type", "library"),
                "license": _extract_license(comp),
                "is_direct": True,
                "extra_data": comp,
            }
        )
    return deps


async def parse_spdx(raw: dict) -> list[dict]:
    deps = []
    packages = raw.get("packages", [])
    for pkg in packages:
        deps.append(
            {
                "name": pkg.get("name", ""),
                "version": pkg.get("versionInfo", ""),
                "purl": "",
                "dep_type": "library",
                "license": pkg.get("licenseDeclared", ""),
                "is_direct": True,
                "extra_data": pkg,
            }
        )
    return deps


def _extract_license(component: dict) -> str:
    licenses = component.get("licenses", [])
    for lic in licenses:
        if "license" in lic:
            return lic["license"].get("id", "")
    return ""


def _extract_timestamp(raw: dict) -> datetime | None:
    ts = (raw.get("metadata") or {}).get("timestamp")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


async def store_sbom(
    db: AsyncSession,
    project_id: str,
    raw: dict,
    version: str | None = None,
    service_name: str | None = None,
) -> SBOM:
    fmt = raw.get("bomFormat", "").lower()
    if fmt == "cyclonedx":
        deps_data = await parse_cyclonedx(raw)
        fmt = "cyclonedx"
    elif raw.get("spdxVersion"):
        deps_data = await parse_spdx(raw)
        fmt = "spdx"
    else:
        deps_data = []

    sha = compute_sha256(raw)
    version = version or _extract_component_version(raw) or sha

    result = await db.execute(select(SBOM).where(SBOM.sha256 == sha))
    existing = result.scalar_one_or_none()
    if existing:
        return existing

    auto_service = _extract_service_name(raw)
    effective_name = service_name or auto_service
    if effective_name:
        service = await _get_or_create_service(db, project_id, effective_name)
    else:
        service = None

    created_at = _extract_timestamp(raw)

    sbom = SBOM(
        project_id=project_id,
        version=version,
        format=fmt,
        raw_sbom=raw,
        sha256=sha,
        dependency_count=len(deps_data),
        service_id=service.id if service else None,
        created_at=created_at,
    )
    # uploaded_at set via server_default at DB level
    db.add(sbom)
    await db.flush()

    for dep_data in deps_data:
        dep = Dependency(sbom_id=sbom.id, **dep_data)
        db.add(dep)

    return sbom
