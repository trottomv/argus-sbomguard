"""Read-only MCP (Model Context Protocol) server for AI agents.

Exposes a curated set of read-only tools over the same data the web UI and
REST API operate on. Tools never trigger scans, rescans or uploads; each
invocation opens its own ``async_session_factory`` session (the same pattern
as ``services/tasks.py``) so no state leaks across calls.

Pure service layer: the tool functions, the ``build_mcp_server`` factory and
``mcp_transport_security`` (the DNS-rebinding allow-list that always permits
loopback hosts, the configured ``domain`` and the ``host:*`` patterns derived
from the shared ``allowed_hosts`` setting). The HTTP composition — server
instantiation, transport, bearer-auth wrapper, 404 gate and router mount —
lives in ``api.mcp_server``.
"""

import json
import uuid
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from sqlalchemy import func, select

from config import settings
from database import async_session_factory
from models.acceptance import RiskAcceptance
from models.alert import AlertRule
from models.project import Project
from models.sbom import SBOM, Dependency
from models.service import Service
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)
from services.acceptance import covered_by_acceptance
from services.vulnerability_queries import apply_vuln_ordering, build_vuln_subquery

# The SDK's DNS-rebinding check accepts a Host either by exact match or as
# ``host:<port>``; clients behind a standard HTTPS/HTTP proxy send the bare
# hostname (no explicit port), so each entry is added in both forms.
_DEFAULT_ALLOWED_HOSTS = (
    "localhost",
    "localhost:*",
    "127.0.0.1",
    "127.0.0.1:*",
    "[::1]",
    "[::1]:*",
)


def _dump(value: Any) -> str:
    """JSON-serialize tool output (datetimes/UUIDs fall back to ISO strings)."""
    return json.dumps(value, default=str, ensure_ascii=False)


def _enum_text(value: Any) -> str | None:
    """Normalize an ORM enum column to its persisted string value.

    SQLAlchemy returns the declared Python enum (a ``str`` subclass here) or,
    depending on the load path, the raw stored string; both are safe.
    """
    if value is None:
        return None
    return str(getattr(value, "value", value))


def _fix_info(vuln: Vulnerability) -> dict:
    """Fixed versions and fix state for a vulnerability.

    Grype's ``vulnerability.fix`` object (``versions``/``state``) is stored in
    ``Vulnerability.extra_data``; the ``fixed_versions`` column is not populated
    by the scanner, so the stored payload is the source of truth.
    """
    fix = (vuln.extra_data or {}).get("fix") or {}
    return {
        "fixed_versions": list(fix.get("versions") or []),
        "fix_state": fix.get("state"),
    }


def mcp_transport_security() -> TransportSecuritySettings:
    """Build the DNS-rebinding allow-list for the MCP transport.

    Loopback hosts, the configured public ``domain`` and the exact hostnames
    listed in ``allowed_hosts`` are accepted (each as the bare hostname and as
    a ``host:*`` pattern, so requests with or without an explicit port pass).
    A ``*`` entry (the default "allow any host" of the app-wide
    TrustedHostMiddleware) and ``*.domain`` subdomain wildcards cannot be
    expressed by the SDK's allow-list and are deliberately skipped: the MCP
    endpoint still protects against DNS rebinding for the loopback/domain set,
    so pin exact hostnames in ``allowed_hosts`` when the MCP endpoint is used.
    """
    hosts = list(_DEFAULT_ALLOWED_HOSTS)
    for allowed in settings.allowed_hosts:
        if allowed == "*" or allowed.startswith("*"):
            continue
        base = allowed[:-2] if allowed.endswith(":*") else allowed
        hosts.extend((base, f"{base}:*"))
    if settings.domain:
        hosts.extend((settings.domain, f"{settings.domain}:*"))
    return TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=hosts)


def _project_dict(project: Project) -> dict:
    return {
        "id": str(project.id),
        "name": project.name,
        "slug": project.slug,
        "description": project.description,
        "repo_url": project.repo_url,
        "platform": project.platform,
        "created_at": project.created_at,
    }


async def list_projects(offset: int = 0, limit: int = 50) -> str:
    """List all projects (name, slug, repo URL, platform, timestamps), paginated."""
    if error := _validate_page(offset, limit):
        return _dump({"error": error})
    async with async_session_factory() as db:
        base = select(Project).order_by(Project.created_at.desc(), Project.id)
        total = await _count(db, base)
        result = await db.execute(base.offset(offset).limit(limit + 1))
        projects = result.scalars().all()
    return _dump(
        _page_envelope(
            [_project_dict(project) for project in projects[:limit]], total, offset, limit
        )
    )


async def list_services(project_id: str, offset: int = 0, limit: int = 50) -> str:
    """List the services of a project (pass the project UUID), paginated."""
    if error := _validate_page(offset, limit):
        return _dump({"error": error})
    try:
        project_uuid = uuid.UUID(project_id)
    except ValueError:
        return _dump({"error": "project_id must be a valid UUID"})
    async with async_session_factory() as db:
        project = (
            await db.execute(select(Project).where(Project.id == project_uuid))
        ).scalar_one_or_none()
        if project is None:
            return _dump({"error": "Project not found"})
        base = select(Service).where(Service.project_id == project_uuid).order_by(Service.name)
        total = await _count(db, base)
        result = await db.execute(base.offset(offset).limit(limit + 1))
        services = result.scalars().all()
    return _dump(
        _page_envelope(
            [
                {
                    "id": str(service.id),
                    "project_id": str(project_uuid),
                    "name": service.name,
                    "created_at": service.created_at,
                }
                for service in services[:limit]
            ],
            total,
            offset,
            limit,
        )
    )


async def list_sboms(
    project_id: str | None = None,
    service_id: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> str:
    """List SBOMs, newest first, optionally filtered by project or service, paginated."""
    if error := _validate_page(offset, limit):
        return _dump({"error": error})
    if project_id is not None:
        try:
            project_id = str(uuid.UUID(project_id))
        except ValueError:
            return _dump({"error": "project_id must be a valid UUID"})
    if service_id is not None:
        try:
            service_id = str(uuid.UUID(service_id))
        except ValueError:
            return _dump({"error": "service_id must be a valid UUID"})

    query = (
        select(SBOM, Project.name, Service.name)
        .join(Project, SBOM.project_id == Project.id)
        .outerjoin(Service, SBOM.service_id == Service.id)
        .order_by(SBOM.uploaded_at.desc(), SBOM.id)
    )
    if project_id is not None:
        query = query.where(SBOM.project_id == uuid.UUID(project_id))
    if service_id is not None:
        query = query.where(SBOM.service_id == uuid.UUID(service_id))

    async with async_session_factory() as db:
        total = await _count(db, query)
        rows = (await db.execute(query.offset(offset).limit(limit + 1))).all()
    return _dump(
        _page_envelope(
            [
                {
                    "id": str(sbom.id),
                    "project_id": str(sbom.project_id),
                    "project_name": project_name,
                    "service_id": str(sbom.service_id) if sbom.service_id else None,
                    "service_name": service_name,
                    "version": sbom.version,
                    "format": _enum_text(sbom.format),
                    "sha256": sbom.sha256,
                    "dependency_count": sbom.dependency_count,
                    "uploaded_at": sbom.uploaded_at,
                }
                for sbom, project_name, service_name in rows[:limit]
            ],
            total,
            offset,
            limit,
        )
    )


_PAGE_LIMIT_DEFAULT = 200
_PAGE_LIMIT_MAX = 500


async def _load_sbom(db, sbom_id: str) -> tuple[SBOM | None, str | None]:
    """Load an SBOM by id, returning ``(sbom, error_message)``."""
    try:
        sbom_uuid = uuid.UUID(sbom_id)
    except ValueError:
        return None, "sbom_id must be a valid UUID"
    sbom = (await db.execute(select(SBOM).where(SBOM.id == sbom_uuid))).scalar_one_or_none()
    if sbom is None:
        return None, "SBOM not found"
    return sbom, None


def _validate_page(offset: int, limit: int) -> str | None:
    """Return an error message when the offset/limit window is invalid."""
    if offset < 0:
        return "offset must be >= 0"
    if limit < 1 or limit > _PAGE_LIMIT_MAX:
        return f"limit must be between 1 and {_PAGE_LIMIT_MAX}"
    return None


async def _count(db, base) -> int:
    """Count the rows a filtered query would return (ordering dropped)."""
    return (
        await db.execute(select(func.count()).select_from(base.order_by(None).subquery()))
    ).scalar() or 0


def _page_envelope(items: list, total: int, offset: int, limit: int) -> dict:
    """Uniform pagination envelope shared by every list tool."""
    return {
        "items": items,
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + len(items) < total,
    }


async def get_sbom(sbom_id: str) -> str:
    """Get SBOM metadata and vulnerability counts (no dependency/vulnerability lists).

    Use ``get_sbom_dependencies`` / ``get_sbom_vulnerabilities`` for the paginated lists.
    """
    async with async_session_factory() as db:
        sbom, error = await _load_sbom(db, sbom_id)
        if error:
            return _dump({"error": error})

        project_name = (
            await db.execute(select(Project.name).where(Project.id == sbom.project_id))
        ).scalar_one()
        service_name = None
        if sbom.service_id is not None:
            service_name = (
                await db.execute(select(Service.name).where(Service.id == sbom.service_id))
            ).scalar_one()

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        status_counts = {"open": 0, "fixed": 0}
        rows = (
            await db.execute(
                select(Vulnerability.severity, SBOMVulnerability.status, func.count())
                .join(SBOMVulnerability, SBOMVulnerability.vulnerability_id == Vulnerability.id)
                .where(SBOMVulnerability.sbom_id == sbom.id)
                .group_by(Vulnerability.severity, SBOMVulnerability.status)
            )
        ).all()
        for severity, status, count in rows:
            counts[(_enum_text(severity) or "unknown").lower()] += count
            status_counts[_enum_text(status)] += count

    return _dump(
        {
            "id": str(sbom.id),
            "project_id": str(sbom.project_id),
            "project_name": project_name,
            "service_id": str(sbom.service_id) if sbom.service_id else None,
            "service_name": service_name,
            "version": sbom.version,
            "format": _enum_text(sbom.format),
            "sha256": sbom.sha256,
            "dependency_count": sbom.dependency_count,
            "uploaded_at": sbom.uploaded_at,
            "vulnerability_counts": {**counts, "total": sum(counts.values())},
            "open_count": status_counts["open"],
            "fixed_count": status_counts["fixed"],
        }
    )


async def get_sbom_dependencies(
    sbom_id: str,
    offset: int = 0,
    limit: int = _PAGE_LIMIT_DEFAULT,
    dep_type: str | None = None,
    direct_only: bool = False,
) -> str:
    """List an SBOM's dependencies, paginated (offset/limit, max 500)."""
    if error := _validate_page(offset, limit):
        return _dump({"error": error})
    async with async_session_factory() as db:
        sbom, error = await _load_sbom(db, sbom_id)
        if error:
            return _dump({"error": error})

        base = select(Dependency).where(Dependency.sbom_id == sbom.id)
        if dep_type is not None:
            base = base.where(Dependency.dep_type == dep_type)
        if direct_only:
            base = base.where(Dependency.is_direct.is_(True))

        total = await _count(db, base)
        rows = (
            (
                await db.execute(
                    base.order_by(
                        Dependency.name, Dependency.version, Dependency.purl, Dependency.id
                    )
                    .offset(offset)
                    .limit(limit + 1)
                )
            )
            .scalars()
            .all()
        )

    has_more = len(rows) > limit
    return _dump(
        {
            "sbom_id": str(sbom.id),
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
            "dependencies": [
                {
                    "name": dep.name,
                    "version": dep.version,
                    "purl": dep.purl,
                    "type": dep.dep_type,
                    "license": dep.license,
                    "is_direct": dep.is_direct,
                }
                for dep in rows[:limit]
            ],
        }
    )


async def get_sbom_vulnerabilities(
    sbom_id: str,
    offset: int = 0,
    limit: int = _PAGE_LIMIT_DEFAULT,
    status: str | None = None,
    severity: str | None = None,
) -> str:
    """List an SBOM's vulnerabilities, paginated, with optional status/severity filters."""
    if error := _validate_page(offset, limit):
        return _dump({"error": error})
    async with async_session_factory() as db:
        sbom, error = await _load_sbom(db, sbom_id)
        if error:
            return _dump({"error": error})

        base = (
            select(Vulnerability, SBOMVulnerability)
            .join(SBOMVulnerability, SBOMVulnerability.vulnerability_id == Vulnerability.id)
            .where(SBOMVulnerability.sbom_id == sbom.id)
        )
        if status is not None:
            base = base.where(func.lower(SBOMVulnerability.status) == status.lower())
        if severity:
            base = base.where(Vulnerability.severity.ilike(severity.replace("\x00", "")))

        total = await _count(db, base)
        rows = (
            await db.execute(base.order_by(Vulnerability.cve_id).offset(offset).limit(limit + 1))
        ).all()

    has_more = len(rows) > limit
    return _dump(
        {
            "sbom_id": str(sbom.id),
            "total": total,
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
            "vulnerabilities": [
                {
                    "cve_id": vuln.cve_id,
                    "severity": _enum_text(vuln.severity),
                    "cvss_score": vuln.cvss_score,
                    "summary": vuln.summary,
                    "status": _enum_text(link.status),
                    "dependency_purl": link.dependency_purl,
                    **_fix_info(vuln),
                }
                for vuln, link in rows[:limit]
            ],
        }
    )


async def list_vulnerabilities(
    severity: str | None = None,
    project_id: str | None = None,
    service_id: str | None = None,
    cve_id: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> str:
    """List currently open vulnerabilities, paginated, with optional filters.

    ``severity`` is a case-insensitive exact match; ``cve_id`` is a
    case-insensitive substring filter.
    """
    if error := _validate_page(offset, limit):
        return _dump({"error": error})
    for field_name, value in (("project_id", project_id), ("service_id", service_id)):
        if value is not None:
            try:
                uuid.UUID(value)
            except ValueError:
                return _dump({"error": f"{field_name} must be a valid UUID"})

    async with async_session_factory() as db:
        query = select(Vulnerability).where(
            Vulnerability.id.in_(build_vuln_subquery(severity, project_id, service_id, cve_id))
        )
        query = apply_vuln_ordering(query, "severity", "desc").order_by(Vulnerability.id)
        total = await _count(db, query)
        rows = (await db.execute(query.offset(offset).limit(limit + 1))).scalars().all()
        vulns = rows[:limit]
        if not vulns:
            return _dump(_page_envelope([], total, offset, limit))

        vuln_ids = [vuln.id for vuln in vulns]
        project_map: dict[str, set[str]] = {}
        service_map: dict[str, set[str]] = {}
        purl_map: dict[str, set[str]] = {}
        link_rows = (
            await db.execute(
                select(
                    SBOMVulnerability.vulnerability_id,
                    SBOM.project_id,
                    Service.name,
                    SBOMVulnerability.dependency_purl,
                )
                .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
                .outerjoin(Service, SBOM.service_id == Service.id)
                .where(
                    SBOMVulnerability.status == VulnerabilityStatus.OPEN,
                    SBOMVulnerability.vulnerability_id.in_(vuln_ids),
                )
                .where(~covered_by_acceptance(SBOMVulnerability, SBOM))
            )
        ).all()
        project_ids = {row[1] for row in link_rows if row[1] is not None}
        project_names: dict[str, str] = {}
        if project_ids:
            name_rows = await db.execute(
                select(Project.id, Project.name).where(Project.id.in_(project_ids))
            )
            project_names = {str(row[0]): row[1] for row in name_rows}
        for vuln_id, project_id_val, service_name, purl in link_rows:
            if project_id_val is not None:
                name = project_names.get(str(project_id_val))
                if name:
                    project_map.setdefault(str(vuln_id), set()).add(name)
            if service_name:
                service_map.setdefault(str(vuln_id), set()).add(service_name)
            if purl:
                purl_map.setdefault(str(vuln_id), set()).add(purl)

        items = [
            {
                "id": str(vuln.id),
                "cve_id": vuln.cve_id,
                "severity": _enum_text(vuln.severity),
                "cvss_score": vuln.cvss_score,
                "epss_score": vuln.epss_score,
                "epss_percentile": vuln.epss_percentile,
                "summary": vuln.summary,
                "source": vuln.source,
                "published_at": vuln.published_at,
                "projects": sorted(project_map.get(str(vuln.id), [])),
                "services": sorted(service_map.get(str(vuln.id), [])),
                "dependency_purls": sorted(purl_map.get(str(vuln.id), [])),
                **_fix_info(vuln),
            }
            for vuln in vulns
        ]
    return _dump(_page_envelope(items, total, offset, limit))


async def summarize_vulnerabilities() -> str:
    """Return the platform-wide vulnerability posture (open counts, fixed)."""
    async with async_session_factory() as db:
        open_rows = (
            await db.execute(
                select(Vulnerability.id, Vulnerability.severity)
                .join(SBOMVulnerability)
                .join(SBOM, SBOMVulnerability.sbom_id == SBOM.id)
                .where(SBOMVulnerability.status == VulnerabilityStatus.OPEN)
                .where(~covered_by_acceptance(SBOMVulnerability, SBOM))
                .distinct(Vulnerability.id)
            )
        ).all()

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for _, severity in open_rows:
            key = "unknown" if severity is None else str(severity).lower()
            counts[key] += 1

        affected_projects = (
            await db.execute(
                select(func.count(func.distinct(SBOM.project_id)))
                .select_from(SBOM)
                .join(SBOMVulnerability, SBOMVulnerability.sbom_id == SBOM.id)
                .where(SBOMVulnerability.status == VulnerabilityStatus.OPEN)
                .where(~covered_by_acceptance(SBOMVulnerability, SBOM))
            )
        ).scalar() or 0

        affected_services = (
            await db.execute(
                select(func.count(func.distinct(SBOM.service_id)))
                .select_from(SBOM)
                .join(SBOMVulnerability, SBOMVulnerability.sbom_id == SBOM.id)
                .where(
                    SBOMVulnerability.status == VulnerabilityStatus.OPEN,
                    SBOM.service_id.isnot(None),
                )
                .where(~covered_by_acceptance(SBOMVulnerability, SBOM))
            )
        ).scalar() or 0

        fixed = (
            await db.execute(
                select(func.count(func.distinct(SBOMVulnerability.vulnerability_id))).where(
                    SBOMVulnerability.status == VulnerabilityStatus.FIXED
                )
            )
        ).scalar() or 0

    return _dump(
        {
            "counts": counts,
            "total": sum(counts.values()),
            "affected_projects": affected_projects,
            "affected_services": affected_services,
            "fixed": fixed,
        }
    )


async def get_snapshot(days: int = 30) -> str:
    """Return the platform-wide daily vulnerability snapshot trend."""
    if days < 1 or days > 365:
        return _dump({"error": "days must be between 1 and 365"})
    async with async_session_factory() as db:
        rows = (
            await db.execute(
                select(
                    VulnerabilitySnapshot.snapshot_date,
                    VulnerabilitySnapshot.critical_count,
                    VulnerabilitySnapshot.high_count,
                    VulnerabilitySnapshot.medium_count,
                    VulnerabilitySnapshot.low_count,
                    VulnerabilitySnapshot.fixed_count,
                    VulnerabilitySnapshot.total_dependencies,
                )
                .where(VulnerabilitySnapshot.project_id.is_(None))
                .order_by(VulnerabilitySnapshot.snapshot_date.desc())
                .limit(days)
            )
        ).all()

    snapshots = [
        {
            "date": str(row.snapshot_date),
            "critical": row.critical_count,
            "high": row.high_count,
            "medium": row.medium_count,
            "low": row.low_count,
            "fixed": row.fixed_count,
            "total_dependencies": row.total_dependencies,
        }
        for row in reversed(rows)
    ]
    return _dump({"count": len(snapshots), "snapshots": snapshots})


async def list_alerts(offset: int = 0, limit: int = 50) -> str:
    """List alert rules (per-project thresholds and notification channels), paginated."""
    if error := _validate_page(offset, limit):
        return _dump({"error": error})
    async with async_session_factory() as db:
        base = (
            select(AlertRule, Project.name)
            .join(Project, AlertRule.project_id == Project.id)
            .order_by(AlertRule.created_at.desc(), AlertRule.id)
        )
        total = await _count(db, base)
        rows = (await db.execute(base.offset(offset).limit(limit + 1))).all()
    return _dump(
        _page_envelope(
            [
                {
                    "id": str(alert.id),
                    "project_id": str(alert.project_id),
                    "project_name": project_name,
                    "severity_threshold": _enum_text(alert.severity_threshold),
                    "notification_type": _enum_text(alert.notification_type),
                    "enabled": alert.enabled,
                    "config": alert.config,
                    "created_at": alert.created_at,
                }
                for alert, project_name in rows[:limit]
            ],
            total,
            offset,
            limit,
        )
    )


async def list_risk_acceptances(
    project_id: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> str:
    """List accepted vulnerabilities (risk acceptances), paginated."""
    if error := _validate_page(offset, limit):
        return _dump({"error": error})
    if project_id is not None:
        try:
            project_id = str(uuid.UUID(project_id))
        except ValueError:
            return _dump({"error": "project_id must be a valid UUID"})

    query = (
        select(RiskAcceptance, Vulnerability.cve_id, Project.name, Service.name)
        .join(Vulnerability, RiskAcceptance.vulnerability_id == Vulnerability.id)
        .join(Project, RiskAcceptance.project_id == Project.id)
        .outerjoin(Service, RiskAcceptance.service_id == Service.id)
        .order_by(RiskAcceptance.created_at.desc(), RiskAcceptance.id)
    )
    if project_id is not None:
        query = query.where(RiskAcceptance.project_id == uuid.UUID(project_id))

    async with async_session_factory() as db:
        total = await _count(db, query)
        rows = (await db.execute(query.offset(offset).limit(limit + 1))).all()
    return _dump(
        _page_envelope(
            [
                {
                    "id": str(acceptance.id),
                    "project_id": str(acceptance.project_id),
                    "project_name": project_name,
                    "service_id": str(acceptance.service_id) if acceptance.service_id else None,
                    "service_name": service_name,
                    "vulnerability_id": str(acceptance.vulnerability_id),
                    "cve_id": cve_id,
                    "reason": acceptance.reason,
                    "created_at": acceptance.created_at,
                }
                for acceptance, cve_id, project_name, service_name in rows[:limit]
            ],
            total,
            offset,
            limit,
        )
    )


def build_mcp_server() -> MCPServer:
    """Build the MCP server with the read-only tool set registered."""
    server = MCPServer(
        "argus-sbomguard",
        version=settings.app_version,
        log_level="WARNING",
    )
    tools = [
        (list_projects, "List all projects (name, slug, repo URL, platform), paginated."),
        (list_services, "List the services of a project (project_id UUID), paginated."),
        (
            list_sboms,
            "List SBOMs newest-first, optionally filtered by project_id/service_id, paginated.",
        ),
        (
            get_sbom,
            "Get SBOM metadata and vulnerability counts (no dependency/vulnerability lists).",
        ),
        (
            get_sbom_dependencies,
            "List an SBOM's dependencies, paginated (offset/limit, max 500).",
        ),
        (
            get_sbom_vulnerabilities,
            "List an SBOM's vulnerabilities, paginated, with optional status/severity filters.",
        ),
        (
            list_vulnerabilities,
            "List currently open vulnerabilities, with optional severity/project/service/cve filters, paginated.",
        ),
        (
            summarize_vulnerabilities,
            "Platform-wide vulnerability posture (open counts, fixed, affected).",
        ),
        (get_snapshot, "Platform-wide daily vulnerability snapshot trend for the last N days."),
        (
            list_alerts,
            "List alert rules (per-project thresholds and notification channels), paginated.",
        ),
        (
            list_risk_acceptances,
            "List accepted vulnerabilities (risk acceptances), optionally filtered by project_id.",
        ),
    ]
    for tool_fn, description in tools:
        server.tool(description=description)(tool_fn)
    return server
