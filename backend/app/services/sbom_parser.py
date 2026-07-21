import hashlib
import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sbom import SBOM, Dependency


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


async def store_sbom(
    db: AsyncSession,
    project_id: str,
    raw: dict,
    version: str | None = None,
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

    result = await db.execute(select(SBOM).where(SBOM.sha256 == sha))
    existing = result.scalar_one_or_none()
    if existing:
        return existing

    sbom = SBOM(
        project_id=project_id,
        version=version,
        format=fmt,
        raw_sbom=raw,
        sha256=sha,
        dependency_count=len(deps_data),
    )
    db.add(sbom)
    await db.flush()

    for dep_data in deps_data:
        dep = Dependency(sbom_id=sbom.id, **dep_data)
        db.add(dep)

    return sbom
