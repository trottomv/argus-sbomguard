"""Tests for the read-only MCP server and its bearer-token auth wrapper.

The tools are exercised through the SDK's in-memory transport (a real MCP
client-server session) against the test database; the ASGI auth middleware is
tested both in isolation and wired into ``main`` (404 gate when disabled, 401
when enabled but unauthenticated).
"""

import asyncio
import json
from contextlib import asynccontextmanager, suppress
from datetime import UTC, date, datetime, timedelta
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest
from mcp import ClientSession
from mcp.shared.memory import create_client_server_memory_streams
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.responses import JSONResponse

import main
from config import settings
from middleware import mcp_auth as mcp_auth_module
from middleware.mcp_auth import MCPAuthMiddleware
from models.alert import AlertConfig, NotificationChannel, SeverityThreshold
from models.auth import ApiKey, User
from models.project import Project
from models.sbom import SBOM, Dependency, SBOMFormat
from models.service import Service
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)
from services import mcp_server as mcp_server_module
from services.auth import create_api_key

EXPECTED_TOOLS = {
    "list_projects",
    "list_services",
    "list_sboms",
    "get_sbom",
    "list_vulnerabilities",
    "summarize_vulnerabilities",
    "get_snapshot",
    "list_alerts",
}


def _session_factory_for(db_session: AsyncSession) -> async_sessionmaker:
    return async_sessionmaker(db_session.bind, class_=AsyncSession, expire_on_commit=False)


@asynccontextmanager
async def _client_session(server):
    """Drive an MCP server over the SDK in-memory transport and yield a client."""
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        server_task = asyncio.create_task(
            server._lowlevel_server.run(
                server_streams[0],
                server_streams[1],
                server._lowlevel_server.create_initialization_options(),
            )
        )
        try:
            async with ClientSession(client_streams[0], client_streams[1]) as client:
                await client.initialize()
                yield client
        finally:
            server_task.cancel()
            with suppress(asyncio.CancelledError):
                await server_task


async def _call_tool(db_session, monkeypatch, name: str, arguments: dict):
    """Call one MCP tool against the test DB via an in-memory client session."""
    factory = _session_factory_for(db_session)
    monkeypatch.setattr(mcp_server_module, "async_session_factory", factory)
    server = mcp_server_module.build_mcp_server()
    async with _client_session(server) as client:
        result = await client.call_tool(name, arguments)
    assert result.is_error is False, result
    return json.loads(result.content[0].text)


async def _seed_project(db: AsyncSession, name: str = "Alpha"):
    project = Project(
        name=name,
        description="flagship",
        repo_url="https://github.com/acme/alpha",
        platform="github",
    )
    db.add(project)
    await db.flush()
    return project


async def _seed_sbom(
    db: AsyncSession,
    project: Project,
    *,
    with_service: bool = True,
    sbom_format: SBOMFormat | None = SBOMFormat.CYCLONEDX,
):
    service = None
    if with_service:
        service = Service(project_id=project.id, name="api")
        db.add(service)
        await db.flush()
    sbom = SBOM(
        project_id=project.id,
        service_id=service.id if service else None,
        version="1.2.3",
        format=sbom_format,
        raw_sbom={"bomFormat": "CycloneDX", "components": []},
        sha256=f"{uuid4().hex}{uuid4().hex}",
        dependency_count=1,
    )
    db.add(sbom)
    await db.flush()
    db.add(
        Dependency(
            sbom_id=sbom.id,
            name="lodash",
            version="4.17.20",
            purl="pkg:npm/lodash@4.17.20",
            is_direct=True,
        )
    )
    vuln = Vulnerability(
        cve_id=f"CVE-2026-{uuid4().hex[:6]}",
        source="grype",
        severity=VulnerabilitySeverity.HIGH,
        cvss_score=8.1,
        summary="lodash prototype pollution",
        published_at=datetime.now(UTC),
    )
    db.add(vuln)
    await db.flush()
    db.add(
        SBOMVulnerability(
            sbom_id=sbom.id,
            dependency_purl="pkg:npm/lodash@4.17.20",
            vulnerability_id=vuln.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )
    await db.commit()
    return sbom, service, vuln


# --------------------------------------------------------------------------- #
# MCP transport security (shares the app-wide ALLOWED_HOSTS allow-list)
# --------------------------------------------------------------------------- #


def test_mcp_transport_security_uses_allowed_hosts_and_domain(monkeypatch):
    monkeypatch.setattr(settings, "allowed_hosts", ["argus.example.com", "api.internal:*"])
    monkeypatch.setattr(settings, "domain", "argus.example.com")
    security = mcp_server_module.mcp_transport_security()
    assert security.enable_dns_rebinding_protection is True
    assert {
        "localhost:*",
        "127.0.0.1:*",
        "[::1]:*",
        "argus.example.com:*",
        "api.internal:*",
    } <= set(security.allowed_hosts)


def test_mcp_transport_security_skips_wildcard_and_missing_domain(monkeypatch):
    monkeypatch.setattr(settings, "allowed_hosts", ["*"])
    monkeypatch.setattr(settings, "domain", "")
    security = mcp_server_module.mcp_transport_security()
    assert set(security.allowed_hosts) == {"localhost:*", "127.0.0.1:*", "[::1]:*"}


# --------------------------------------------------------------------------- #
# Tools — protocol + read-only surface
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_build_mcp_server_registers_read_only_tools():
    server = mcp_server_module.build_mcp_server()
    names = {tool.name for tool in await server.list_tools()}
    assert names == EXPECTED_TOOLS


def test_module_server_transport_and_session_manager_exposed():
    assert mcp_server_module.mcp_transport_app is not None
    assert mcp_server_module.mcp_server.session_manager is not None


# --------------------------------------------------------------------------- #
# Tools — happy paths against seeded data
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_tools_against_seeded_data(db_session, monkeypatch):
    project = await _seed_project(db_session)
    sbom, service, vuln = await _seed_sbom(db_session, project)

    db_session.add(
        VulnerabilitySnapshot(
            project_id=None,
            snapshot_date=date.today(),
            critical_count=1,
            high_count=1,
            medium_count=0,
            low_count=1,
            fixed_count=2,
            total_dependencies=10,
        )
    )
    db_session.add(
        AlertConfig(
            project_id=project.id,
            severity_threshold=SeverityThreshold.HIGH,
            notification_type=NotificationChannel.EMAIL,
            enabled=True,
        )
    )
    await db_session.commit()

    factory = _session_factory_for(db_session)
    monkeypatch.setattr(mcp_server_module, "async_session_factory", factory)
    server = mcp_server_module.build_mcp_server()

    async with _client_session(server) as client:
        listed = await client.list_tools()
        assert {tool.name for tool in listed.tools} == EXPECTED_TOOLS

        projects = json.loads((await client.call_tool("list_projects", {})).content[0].text)
        assert len(projects) == 1
        assert projects[0]["name"] == "Alpha"
        assert projects[0]["slug"] == project.slug
        assert projects[0]["repo_url"] == "https://github.com/acme/alpha"
        assert projects[0]["platform"] == "github"
        assert projects[0]["id"] == str(project.id)
        assert projects[0]["created_at"]

        services = json.loads(
            (await client.call_tool("list_services", {"project_id": str(project.id)}))
            .content[0]
            .text
        )
        assert len(services) == 1
        assert services[0]["name"] == "api"
        assert services[0]["project_id"] == str(project.id)
        assert services[0]["id"] == str(service.id)

        sboms = json.loads((await client.call_tool("list_sboms", {})).content[0].text)
        assert len(sboms) == 1
        assert sboms[0]["project_name"] == "Alpha"
        assert sboms[0]["service_name"] == "api"
        assert sboms[0]["version"] == "1.2.3"
        assert sboms[0]["format"] == "cyclonedx"
        assert sboms[0]["dependency_count"] == 1
        assert sboms[0]["id"] == str(sbom.id)
        assert sboms[0]["uploaded_at"]

        detail = json.loads(
            (await client.call_tool("get_sbom", {"sbom_id": str(sbom.id)})).content[0].text
        )
        assert detail["project_name"] == "Alpha"
        assert detail["service_name"] == "api"
        assert detail["dependencies"] == [
            {
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20",
                "type": None,
                "license": None,
                "is_direct": True,
            }
        ]
        assert detail["vulnerabilities"] == [
            {
                "cve_id": vuln.cve_id,
                "severity": "HIGH",
                "cvss_score": 8.1,
                "summary": "lodash prototype pollution",
                "status": "open",
                "dependency_purl": "pkg:npm/lodash@4.17.20",
            }
        ]

        vulns = json.loads((await client.call_tool("list_vulnerabilities", {})).content[0].text)
        assert len(vulns) == 1
        assert vulns[0]["cve_id"] == vuln.cve_id
        assert vulns[0]["severity"] == "HIGH"
        assert vulns[0]["projects"] == ["Alpha"]
        assert vulns[0]["services"] == ["api"]
        assert vulns[0]["dependency_purls"] == ["pkg:npm/lodash@4.17.20"]
        assert vulns[0]["id"] == str(vuln.id)

        summary = json.loads(
            (await client.call_tool("summarize_vulnerabilities", {})).content[0].text
        )
        assert summary == {
            "counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0},
            "total": 1,
            "affected_projects": 1,
            "affected_services": 1,
            "fixed": 0,
        }

        snapshot = json.loads((await client.call_tool("get_snapshot", {})).content[0].text)
        assert snapshot["count"] == 1
        assert snapshot["snapshots"][0]["critical"] == 1

        alerts = json.loads((await client.call_tool("list_alerts", {})).content[0].text)
        assert len(alerts) == 1
        assert alerts[0]["project_id"] == str(project.id)
        assert alerts[0]["project_name"] == "Alpha"
        assert alerts[0]["severity_threshold"] == "high"
        assert alerts[0]["notification_type"] == "email"
        assert alerts[0]["enabled"] is True


# --------------------------------------------------------------------------- #
# Tools — filters and empty results
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_list_sboms_filters(db_session, monkeypatch):
    project = await _seed_project(db_session)
    sbom, service, _ = await _seed_sbom(db_session, project, with_service=True)
    project_other = await _seed_project(db_session, name="Beta")
    other_sbom, _, _ = await _seed_sbom(
        db_session, project_other, with_service=False, sbom_format=None
    )

    listed = await _call_tool(db_session, monkeypatch, "list_sboms", {"limit": 1})
    assert len(listed) == 1
    beta = await _call_tool(
        db_session, monkeypatch, "list_sboms", {"project_id": str(project_other.id)}
    )
    assert beta[0]["project_name"] == "Beta"
    alpha = await _call_tool(db_session, monkeypatch, "list_sboms", {"project_id": str(project.id)})
    assert alpha[0]["service_name"] == "api"
    scoped = await _call_tool(
        db_session,
        monkeypatch,
        "list_sboms",
        {"project_id": str(project.id), "service_id": str(service.id), "limit": 1},
    )
    assert scoped[0]["id"] == str(sbom.id)
    detached = await _call_tool(
        db_session, monkeypatch, "get_sbom", {"sbom_id": str(other_sbom.id)}
    )
    assert detached["project_name"] == "Beta"
    assert detached["service_name"] is None
    assert detached["format"] is None
    assert await _call_tool(
        db_session, monkeypatch, "list_sboms", {"project_id": "not-a-uuid"}
    ) == {"error": "project_id must be a valid UUID"}
    assert await _call_tool(
        db_session, monkeypatch, "list_sboms", {"service_id": "not-a-uuid"}
    ) == {"error": "service_id must be a valid UUID"}


@pytest.mark.asyncio
async def test_list_sboms_empty_and_vuln_empty(db_session, monkeypatch):
    assert await _call_tool(db_session, monkeypatch, "list_sboms", {}) == []
    assert (
        await _call_tool(db_session, monkeypatch, "list_vulnerabilities", {"severity": "critical"})
        == []
    )


@pytest.mark.asyncio
async def test_get_sbom_not_found_and_invalid(db_session, monkeypatch):
    missing = await _call_tool(
        db_session,
        monkeypatch,
        "get_sbom",
        {"sbom_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert missing == {"error": "SBOM not found"}
    invalid = await _call_tool(db_session, monkeypatch, "get_sbom", {"sbom_id": "zz"})
    assert invalid == {"error": "sbom_id must be a valid UUID"}


@pytest.mark.asyncio
async def test_list_services_errors(db_session, monkeypatch):
    project = await _seed_project(db_session)
    await db_session.commit()

    not_found = await _call_tool(
        db_session,
        monkeypatch,
        "list_services",
        {"project_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert not_found == {"error": "Project not found"}
    invalid = await _call_tool(db_session, monkeypatch, "list_services", {"project_id": "nope"})
    assert invalid == {"error": "project_id must be a valid UUID"}
    assert (
        await _call_tool(db_session, monkeypatch, "list_services", {"project_id": str(project.id)})
        == []
    )


@pytest.mark.asyncio
async def test_list_vulnerabilities_filters_and_errors(db_session, monkeypatch):
    project = await _seed_project(db_session)
    _, _, vuln = await _seed_sbom(db_session, project)

    by_severity = await _call_tool(
        db_session, monkeypatch, "list_vulnerabilities", {"severity": "high"}
    )
    assert by_severity[0]["cve_id"] == vuln.cve_id
    by_project = await _call_tool(
        db_session,
        monkeypatch,
        "list_vulnerabilities",
        {"project_id": str(project.id)},
    )
    assert by_project[0]["projects"] == ["Alpha"]
    by_cve = await _call_tool(
        db_session, monkeypatch, "list_vulnerabilities", {"cve_id": vuln.cve_id[:10]}
    )
    assert len(by_cve) == 1
    assert (
        await _call_tool(db_session, monkeypatch, "list_vulnerabilities", {"severity": "unknown"})
        == []
    )
    assert await _call_tool(
        db_session, monkeypatch, "list_vulnerabilities", {"project_id": "bogus"}
    ) == {"error": "project_id must be a valid UUID"}
    assert await _call_tool(
        db_session, monkeypatch, "list_vulnerabilities", {"service_id": "bogus"}
    ) == {"error": "service_id must be a valid UUID"}


@pytest.mark.asyncio
async def test_summarize_treats_null_severity_as_unknown(db_session, monkeypatch):
    project = await _seed_project(db_session)
    sbom, _, _ = await _seed_sbom(db_session, project)

    null_vuln = Vulnerability(cve_id=f"CVE-2026-{uuid4().hex[:6]}", source="grype", severity=None)
    db_session.add(null_vuln)
    await db_session.flush()
    db_session.add(
        SBOMVulnerability(
            sbom_id=sbom.id,
            dependency_purl="pkg:npm/lodash@4.17.20",
            vulnerability_id=null_vuln.id,
            status=VulnerabilityStatus.OPEN,
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    summary = await _call_tool(db_session, monkeypatch, "summarize_vulnerabilities", {})
    assert summary["counts"]["high"] == 1
    assert summary["counts"]["unknown"] == 1
    assert summary["total"] == 2


@pytest.mark.asyncio
async def test_summarize_fixed_and_get_snapshot_validation(db_session, monkeypatch):
    project = await _seed_project(db_session)
    sbom, _, _ = await _seed_sbom(db_session, project)

    fixed = Vulnerability(
        cve_id="CVE-2026-7777", source="grype", severity=VulnerabilitySeverity.LOW
    )
    db_session.add(fixed)
    await db_session.flush()
    db_session.add(
        SBOMVulnerability(
            sbom_id=sbom.id,
            dependency_purl="pkg:npm/lodash@4.17.20",
            vulnerability_id=fixed.id,
            status=VulnerabilityStatus.FIXED,
            fixed_at=datetime.now(UTC),
            detected_at=datetime.now(UTC),
        )
    )
    await db_session.commit()

    summary = await _call_tool(db_session, monkeypatch, "summarize_vulnerabilities", {})
    assert summary["fixed"] == 1
    assert summary["affected_projects"] == 1

    assert await _call_tool(db_session, monkeypatch, "get_snapshot", {"days": 0}) == {
        "error": "days must be >= 1"
    }
    assert await _call_tool(db_session, monkeypatch, "get_snapshot", {}) == {
        "count": 0,
        "snapshots": [],
    }


@pytest.mark.asyncio
async def test_get_snapshot_returns_chronological_trend(db_session, monkeypatch):
    db_session.add(
        VulnerabilitySnapshot(
            project_id=None,
            snapshot_date=date.today() - timedelta(days=1),
            critical_count=0,
            high_count=2,
            medium_count=0,
            low_count=0,
            fixed_count=1,
            total_dependencies=8,
        )
    )
    db_session.add(
        VulnerabilitySnapshot(
            project_id=None,
            snapshot_date=date.today(),
            critical_count=1,
            high_count=3,
            medium_count=0,
            low_count=1,
            fixed_count=2,
            total_dependencies=10,
        )
    )
    await db_session.commit()

    trend = await _call_tool(db_session, monkeypatch, "get_snapshot", {"days": 10})
    assert trend["count"] == 2
    assert [row["date"] for row in trend["snapshots"]] == [
        str(date.today() - timedelta(days=1)),
        str(date.today()),
    ]
    assert trend["snapshots"][-1]["critical"] == 1


@pytest.mark.asyncio
async def test_list_alerts_empty(db_session, monkeypatch):
    assert await _call_tool(db_session, monkeypatch, "list_alerts", {}) == []


# --------------------------------------------------------------------------- #
# MCP auth middleware
# --------------------------------------------------------------------------- #


async def _make_api_key(db_session: AsyncSession, *, expired: bool = False) -> str:
    user = User(email=f"agent-{uuid4()}@argus.local", is_admin=True)
    db_session.add(user)
    await db_session.flush()
    key, raw = await create_api_key(db_session, user.id, label="mcp-agent")
    if expired:
        key.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()
    return raw


def _authed_client(db_session, monkeypatch) -> httpx.AsyncClient:
    factory = _session_factory_for(db_session)
    monkeypatch.setattr(mcp_auth_module, "async_session_factory", factory)

    async def _inner(scope, receive, send):
        response = JSONResponse({"forwarded": True})
        await response(scope, receive, send)

    transport = httpx.ASGITransport(app=MCPAuthMiddleware(_inner))
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_mcp_auth_rejects_missing_and_non_bearer(db_session, monkeypatch):
    async with _authed_client(db_session, monkeypatch) as client:
        missing = await client.get("/")
        assert missing.status_code == 401
        assert missing.json() == {"detail": "Bearer token required"}
        assert missing.headers["www-authenticate"] == "Bearer"

        basic = await client.get("/", headers={"Authorization": "Basic Zm9v"})
        assert basic.status_code == 401
        assert basic.json() == {"detail": "Bearer token required"}

        blank = await client.get("/", headers={"Authorization": "Bearer"})
        assert blank.status_code == 401
        assert blank.json() == {"detail": "Bearer token required"}


@pytest.mark.asyncio
async def test_mcp_auth_rejects_invalid_and_expired_keys(db_session, monkeypatch):
    async with _authed_client(db_session, monkeypatch) as client:
        wrong = await client.get("/", headers={"Authorization": "Bearer argus_not-there"})
        assert wrong.status_code == 401
        assert wrong.json() == {"detail": "Invalid API key"}

        non_prefix = await client.get("/", headers={"Authorization": "Bearer hello"})
        assert non_prefix.status_code == 401
        assert non_prefix.json() == {"detail": "Invalid API key"}

        expired_raw = await _make_api_key(db_session, expired=True)
        expired = await client.get("/", headers={"Authorization": f"Bearer {expired_raw}"})
        assert expired.status_code == 401
        assert expired.json() == {"detail": "API key expired"}
        assert "expired" in expired.headers["www-authenticate"]


@pytest.mark.asyncio
async def test_mcp_auth_allows_valid_key_and_commits_last_used(db_session, monkeypatch):
    raw = await _make_api_key(db_session)
    async with _authed_client(db_session, monkeypatch) as client:
        response = await client.get("/", headers={"Authorization": f"Bearer {raw}"})
    assert response.status_code == 200
    assert response.json() == {"forwarded": True}

    key = (await db_session.execute(select(ApiKey).where(ApiKey.label == "mcp-agent"))).scalar_one()
    assert key.last_used_at is not None


@pytest.mark.asyncio
async def test_mcp_auth_passes_non_http_scopes_through():
    seen: list[str] = []

    async def _inner(scope, receive, send):
        await asyncio.sleep(0)
        seen.append(scope["type"])

    app = MCPAuthMiddleware(_inner)
    await app({"type": "websocket", "headers": []}, None, None)
    assert seen == ["websocket"]


# --------------------------------------------------------------------------- #
# main wiring — mount gate + lifespan
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_mcp_mount_returns_404_when_disabled():
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for path in ("/api/v1/mcp", "/api/v1/mcp/"):
            response = await client.get(path)
            assert response.status_code == 404


@pytest.mark.asyncio
async def test_mcp_mount_requires_auth_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "mcp_enabled", True)
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/mcp")
    assert response.status_code == 401
    assert response.json() == {"detail": "Bearer token required"}
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.asyncio
async def test_mcp_gate_forwards_non_http_scopes(monkeypatch):
    seen: list[str] = []

    async def _stub(scope, receive, send):
        await asyncio.sleep(0)
        seen.append(scope["type"])

    monkeypatch.setattr(main, "mcp_authed_app", _stub)
    await main._mcp_gate({"type": "websocket", "headers": []}, None, None)
    assert seen == ["websocket"]


class _FakeRunner:
    def __init__(self) -> None:
        self.entered = False
        self.exited = False

    async def __aenter__(self):
        self.entered = True
        return None

    async def __aexit__(self, *exc_info) -> bool:
        self.exited = True
        return False


class _FakeSessionManager:
    def __init__(self) -> None:
        self.runs: list[_FakeRunner] = []

    def run(self):
        runner = _FakeRunner()
        self.runs.append(runner)
        return runner


@pytest.mark.asyncio
async def test_lifespan_runs_mcp_session_manager_when_enabled(db_session, monkeypatch):
    factory = _session_factory_for(db_session)
    monkeypatch.setattr(main, "async_session_factory", factory)
    monkeypatch.setattr(main, "start_grpc_server", AsyncMock())
    monkeypatch.setattr(settings, "mcp_enabled", True)
    fake_mcp = type("FakeMCPServer", (), {"session_manager": _FakeSessionManager()})()
    monkeypatch.setattr(main, "mcp_server", fake_mcp)

    async with main.lifespan(main.app):
        assert fake_mcp.session_manager.runs[0].entered
    assert fake_mcp.session_manager.runs[0].exited
