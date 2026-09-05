"""Read-only MCP (Model Context Protocol) server for AI agents.

Exposes a curated set of read-only tools over the same data the web UI and
REST API operate on. Tools never trigger scans, rescans or uploads; each
invocation opens its own ``async_session_factory`` session (the same pattern
as ``services/tasks.py``) so no state leaks across calls.

The module builds a single ``MCPServer`` plus its mounted Streamable HTTP
transport (``mcp_transport_app``) at import time. The transport is an ASGI
app meant to be exposed under the FastAPI application at ``/api/v1/mcp``; its
DNS-rebinding protection always allows loopback hosts and the configured
``domain``, plus the ``host:*`` patterns derived from the shared
``allowed_hosts`` setting (used by the app-wide TrustedHostMiddleware too).
"""

import json
import uuid
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from sqlalchemy import func, select

from config import settings
from database import async_session_factory
from models.alert import AlertConfig
from models.project import Project
from models.sbom import SBOM, Dependency
from models.service import Service
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)
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


async def list_projects(limit: int = 50) -> str:
    """List all projects (name, slug, repo URL, platform, timestamps)."""
    async with async_session_factory() as db:
        result = await db.execute(select(Project).order_by(Project.created_at.desc()).limit(limit))
        projects = result.scalars().all()
    return _dump([_project_dict(project) for project in projects])


async def list_services(project_id: str) -> str:
    """List the services of a project (pass the project UUID)."""
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
        result = await db.execute(
            select(Service).where(Service.project_id == project_uuid).order_by(Service.name)
        )
        services = result.scalars().all()
    return _dump(
        [
            {
                "id": str(service.id),
                "project_id": project_id,
                "name": service.name,
                "created_at": service.created_at,
            }
            for service in services
        ]
    )


async def list_sboms(
    project_id: str | None = None,
    service_id: str | None = None,
    limit: int = 10,
) -> str:
    """List SBOMs, newest first, optionally filtered by project or service."""
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
        .order_by(SBOM.uploaded_at.desc())
        .limit(limit)
    )
    if project_id is not None:
        query = query.where(SBOM.project_id == uuid.UUID(project_id))
    if service_id is not None:
        query = query.where(SBOM.service_id == uuid.UUID(service_id))

    async with async_session_factory() as db:
        rows = (await db.execute(query)).all()
    return _dump(
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
            for sbom, project_name, service_name in rows
        ]
    )


async def get_sbom(sbom_id: str) -> str:
    """Get a single SBOM with its dependencies and known vulnerabilities."""
    try:
        sbom_uuid = uuid.UUID(sbom_id)
    except ValueError:
        return _dump({"error": "sbom_id must be a valid UUID"})
    async with async_session_factory() as db:
        sbom = (await db.execute(select(SBOM).where(SBOM.id == sbom_uuid))).scalar_one_or_none()
        if sbom is None:
            return _dump({"error": "SBOM not found"})

        project_name = (
            await db.execute(select(Project.name).where(Project.id == sbom.project_id))
        ).scalar_one()
        service_name = None
        if sbom.service_id is not None:
            service_name = (
                await db.execute(select(Service.name).where(Service.id == sbom.service_id))
            ).scalar_one()

        deps_result = await db.execute(
            select(Dependency).where(Dependency.sbom_id == sbom_uuid).order_by(Dependency.name)
        )
        deps = deps_result.scalars().all()

        vuln_rows = (
            await db.execute(
                select(Vulnerability, SBOMVulnerability)
                .join(SBOMVulnerability, SBOMVulnerability.vulnerability_id == Vulnerability.id)
                .where(SBOMVulnerability.sbom_id == sbom_uuid)
                .order_by(Vulnerability.severity)
            )
        ).all()

    return _dump(
        {
            "id": sbom_id,
            "project_id": str(sbom.project_id),
            "project_name": project_name,
            "service_id": str(sbom.service_id) if sbom.service_id else None,
            "service_name": service_name,
            "version": sbom.version,
            "format": _enum_text(sbom.format),
            "sha256": sbom.sha256,
            "dependency_count": sbom.dependency_count,
            "uploaded_at": sbom.uploaded_at,
            "dependencies": [
                {
                    "name": dep.name,
                    "version": dep.version,
                    "purl": dep.purl,
                    "type": dep.dep_type,
                    "license": dep.license,
                    "is_direct": dep.is_direct,
                }
                for dep in deps
            ],
            "vulnerabilities": [
                {
                    "cve_id": vuln.cve_id,
                    "severity": _enum_text(vuln.severity),
                    "cvss_score": vuln.cvss_score,
                    "summary": vuln.summary,
                    "status": _enum_text(link.status),
                    "dependency_purl": link.dependency_purl,
                }
                for vuln, link in vuln_rows
            ],
        }
    )


async def list_vulnerabilities(
    severity: str | None = None,
    project_id: str | None = None,
    service_id: str | None = None,
    cve_id: str | None = None,
    limit: int = 50,
) -> str:
    """List currently open vulnerabilities with affected projects/services.

    ``severity`` and ``cve_id`` are substring filters (case-insensitive).
    """
    for field_name, value in (("project_id", project_id), ("service_id", service_id)):
        if value is not None:
            try:
                uuid.UUID(value)
            except ValueError:
                return _dump({"error": f"{field_name} must be a valid UUID"})

    async with async_session_factory() as db:
        query = (
            select(Vulnerability)
            .where(
                Vulnerability.id.in_(build_vuln_subquery(severity, project_id, service_id, cve_id))
            )
            .limit(limit)
        )
        query = apply_vuln_ordering(query, "severity", "desc")
        vulns = (await db.execute(query)).scalars().all()
        if not vulns:
            return _dump([])

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
                "summary": vuln.summary,
                "source": vuln.source,
                "published_at": vuln.published_at,
                "projects": sorted(project_map.get(str(vuln.id), [])),
                "services": sorted(service_map.get(str(vuln.id), [])),
                "dependency_purls": sorted(purl_map.get(str(vuln.id), [])),
            }
            for vuln in vulns
        ]
    return _dump(items)


async def summarize_vulnerabilities() -> str:
    """Return the platform-wide vulnerability posture (open counts, fixed)."""
    async with async_session_factory() as db:
        open_rows = (
            await db.execute(
                select(Vulnerability.id, Vulnerability.severity)
                .join(SBOMVulnerability)
                .where(SBOMVulnerability.status == VulnerabilityStatus.OPEN)
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
    if days < 1:
        return _dump({"error": "days must be >= 1"})
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


async def list_alerts() -> str:
    """List alert rules (per-project thresholds and notification channels)."""
    async with async_session_factory() as db:
        rows = (
            await db.execute(
                select(AlertConfig, Project.name)
                .join(Project, AlertConfig.project_id == Project.id)
                .order_by(AlertConfig.created_at.desc())
            )
        ).all()
    return _dump(
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
            for alert, project_name in rows
        ]
    )


def build_mcp_server() -> MCPServer:
    """Build the MCP server with the read-only tool set registered."""
    server = MCPServer(
        "argus-sbomguard",
        version=settings.app_version,
        log_level="WARNING",
    )
    tools = [
        (list_projects, "List all projects (name, slug, repo URL, platform)."),
        (list_services, "List the services of a project (project_id UUID)."),
        (
            list_sboms,
            "List SBOMs newest-first, optionally filtered by project_id/service_id.",
        ),
        (get_sbom, "Get a single SBOM with dependencies and known vulnerabilities."),
        (
            list_vulnerabilities,
            "List currently open vulnerabilities, with optional severity/project/service/cve filters.",
        ),
        (
            summarize_vulnerabilities,
            "Platform-wide vulnerability posture (open counts, fixed, affected).",
        ),
        (get_snapshot, "Platform-wide daily vulnerability snapshot trend for the last N days."),
        (list_alerts, "List alert rules (per-project thresholds and notification channels)."),
    ]
    for tool_fn, description in tools:
        server.tool(description=description)(tool_fn)
    return server


mcp_server = build_mcp_server()
mcp_transport_app = mcp_server.streamable_http_app(
    streamable_http_path="/",
    transport_security=mcp_transport_security(),
)
