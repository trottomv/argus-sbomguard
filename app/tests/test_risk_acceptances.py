import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select

from models.acceptance import RiskAcceptance
from models.project import Project
from models.sbom import SBOM, SBOMFormat
from models.service import Service
from models.vulnerability import (
    SBOMVulnerability,
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilitySnapshot,
    VulnerabilityStatus,
)
from services.snapshots import do_snapshot_metrics

_LODASH_PURL = "pkg:npm/lodash@4.17.20"


def _sha() -> str:
    return f"{uuid.uuid4().hex}{uuid.uuid4().hex}"


async def _seed_open(
    db_session,
    *,
    name: str,
    cve_id: str,
    service_names: list[str] | None = None,
    severity: VulnerabilitySeverity = VulnerabilitySeverity.CRITICAL,
) -> tuple[Project, list[Service | None]]:
    """Create a project with an open finding, optionally scoped to services."""
    project = Project(name=name)
    db_session.add(project)
    await db_session.flush()

    services: list[Service | None] = []
    if service_names:
        for svc_name in service_names:
            service = Service(project_id=project.id, name=svc_name)
            db_session.add(service)
            await db_session.flush()
            services.append(service)
    else:
        services.append(None)

    vuln = Vulnerability(
        cve_id=cve_id,
        source="grype",
        severity=severity,
        cvss_score=9.8,
        summary=cve_id,
    )
    db_session.add(vuln)
    await db_session.flush()

    for service in services:
        sbom = SBOM(
            project_id=project.id,
            service_id=service.id if service else None,
            version="v1",
            format=SBOMFormat.CYCLONEDX,
            raw_sbom={"bomFormat": "CycloneDX"},
            sha256=_sha(),
        )
        db_session.add(sbom)
        await db_session.flush()
        db_session.add(
            SBOMVulnerability(
                sbom_id=sbom.id,
                dependency_purl=_LODASH_PURL,
                vulnerability_id=vuln.id,
                status=VulnerabilityStatus.OPEN,
                detected_at=datetime.now(UTC),
            )
        )
    await db_session.commit()
    return project, services


async def _accept(client, *, project_id: str, vulnerability_id: str, **extra) -> dict:
    payload = {"project_id": project_id, "vulnerability_id": vulnerability_id, **extra}
    if "reason" not in payload:
        payload["reason"] = "accepted risk"
    resp = await client.post("/api/v1/vulnerabilities/acceptances", json=payload)
    return resp


# ── REST endpoints ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_risk_acceptance_project_scope(client, db_session):
    project, _ = await _seed_open(db_session, name="accept-proj", cve_id="CVE-2026-7001")
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7001")
        )
    ).scalar_one()

    resp = await _accept(
        client,
        project_id=str(project.id),
        vulnerability_id=str(vuln.id),
        reason="accepted: no fix available",
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["project_id"] == str(project.id)
    assert body["vulnerability_id"] == str(vuln.id)
    assert body["service_id"] is None
    assert body["reason"] == "accepted: no fix available"

    row = (
        await db_session.execute(
            select(RiskAcceptance).where(RiskAcceptance.project_id == project.id)
        )
    ).scalar_one()
    assert row.vulnerability_id == vuln.id


@pytest.mark.asyncio
async def test_create_risk_acceptance_service_scope(client, db_session):
    project, services = await _seed_open(
        db_session, name="accept-svc", cve_id="CVE-2026-7002", service_names=["api"]
    )
    service = services[0]
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7002")
        )
    ).scalar_one()

    resp = await _accept(
        client,
        project_id=str(project.id),
        service_id=str(service.id),
        vulnerability_id=str(vuln.id),
    )
    assert resp.status_code == 201
    assert resp.json()["service_id"] == str(service.id)


@pytest.mark.asyncio
async def test_create_risk_acceptance_unknown_project(client, db_session):
    _project_unused, _ = await _seed_open(db_session, name="accept-nop", cve_id="CVE-2026-7003")
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7003")
        )
    ).scalar_one()
    resp = await _accept(
        client,
        project_id=str(uuid.uuid4()),
        vulnerability_id=str(vuln.id),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_risk_acceptance_unknown_vulnerability(client, db_session):
    project, _ = await _seed_open(db_session, name="accept-nov", cve_id="CVE-2026-7004")
    resp = await _accept(
        client,
        project_id=str(project.id),
        vulnerability_id=str(uuid.uuid4()),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_risk_acceptance_service_not_in_project(client, db_session):
    project_a, _ = await _seed_open(db_session, name="accept-a", cve_id="CVE-2026-7005")
    project_b, _ = await _seed_open(db_session, name="accept-b", cve_id="CVE-2026-7006")
    service_b = Service(project_id=project_b.id, name="svc-b")
    db_session.add(service_b)
    await db_session.commit()
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7005")
        )
    ).scalar_one()

    resp = await _accept(
        client,
        project_id=str(project_a.id),
        service_id=str(service_b.id),
        vulnerability_id=str(vuln.id),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_risk_acceptance_conflict(client, db_session):
    project, _ = await _seed_open(db_session, name="accept-conflict", cve_id="CVE-2026-7007")
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7007")
        )
    ).scalar_one()

    resp = await _accept(
        client, project_id=str(project.id), vulnerability_id=str(vuln.id), reason="first"
    )
    assert resp.status_code == 201
    resp = await _accept(
        client, project_id=str(project.id), vulnerability_id=str(vuln.id), reason="second"
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_list_and_delete_risk_acceptances(client, db_session):
    project, _ = await _seed_open(db_session, name="accept-crud", cve_id="CVE-2026-7008")
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7008")
        )
    ).scalar_one()
    await _accept(client, project_id=str(project.id), vulnerability_id=str(vuln.id))

    listing = await client.get("/api/v1/vulnerabilities/acceptances")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    acceptance_id = listing.json()["items"][0]["id"]

    filtered = await client.get(f"/api/v1/vulnerabilities/acceptances?project_id={project.id}")
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1

    missing = await client.delete(
        "/api/v1/vulnerabilities/acceptances/00000000-0000-0000-0000-000000000000"
    )
    assert missing.status_code == 404

    deleted = await client.delete(f"/api/v1/vulnerabilities/acceptances/{acceptance_id}")
    assert deleted.status_code == 204

    # The vulnerability is actionable again.
    listing = await client.get("/api/v1/vulnerabilities/acceptances")
    assert listing.json()["total"] == 0
    active = await client.get("/api/v1/vulnerabilities/active")
    assert len(active.json()["items"]) == 1


@pytest.mark.asyncio
async def test_create_risk_acceptance_insert_race_conflict(client, db_session, monkeypatch):
    project, _ = await _seed_open(db_session, name="race-accept", cve_id="CVE-2026-7014")
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7014")
        )
    ).scalar_one()
    db_session.add(
        RiskAcceptance(
            project_id=project.id,
            vulnerability_id=vuln.id,
            reason="first",
        )
    )
    await db_session.commit()

    class _Empty:
        def scalar_one_or_none(self):
            return None

    real_execute = db_session.execute
    hits = {"n": 0}

    async def fake_execute(stmt, *args, **kwargs):
        cols = getattr(stmt, "column_descriptions", None)
        if cols and cols and cols[0].get("entity") is RiskAcceptance and hits["n"] == 0:
            hits["n"] += 1
            return _Empty()
        return await real_execute(stmt, *args, **kwargs)

    monkeypatch.setattr(db_session, "execute", fake_execute)

    resp = await _accept(
        client,
        project_id=str(project.id),
        vulnerability_id=str(vuln.id),
        reason="second",
    )
    assert resp.status_code == 409

    # A later query flows through the passthrough branch of the fake execute.
    listing = await client.get("/api/v1/vulnerabilities/acceptances")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1


# ── "actionable open" semantics ─────────────────────────────────────────────
@pytest.mark.asyncio
async def test_active_list_and_summary_exclude_accepted(client, db_session):
    project, _ = await _seed_open(db_session, name="exclude-accepted", cve_id="CVE-2026-7009")
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7009")
        )
    ).scalar_one()

    assert len((await client.get("/api/v1/vulnerabilities/active")).json()["items"]) == 1
    assert (await client.get("/api/v1/vulnerabilities/summary")).json()["total"] == 1

    await _accept(client, project_id=str(project.id), vulnerability_id=str(vuln.id))

    assert (await client.get("/api/v1/vulnerabilities/active")).json()["items"] == []
    assert (await client.get("/api/v1/vulnerabilities/summary")).json()["total"] == 0


@pytest.mark.asyncio
async def test_project_acceptance_covers_service_scoped_finding(client, db_session):
    project, _ = await _seed_open(
        db_session, name="cover-service", cve_id="CVE-2026-7010", service_names=["api"]
    )
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7010")
        )
    ).scalar_one()

    await _accept(client, project_id=str(project.id), vulnerability_id=str(vuln.id))

    assert (await client.get("/api/v1/vulnerabilities/active")).json()["items"] == []


@pytest.mark.asyncio
async def test_service_acceptance_only_covers_that_service(client, db_session):
    project, _ = await _seed_open(
        db_session,
        name="partial-service",
        cve_id="CVE-2026-7011",
        service_names=["api", "worker"],
    )
    services = (
        (await db_session.execute(select(Service).where(Service.project_id == project.id)))
        .scalars()
        .all()
    )
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7011")
        )
    ).scalar_one()
    api_svc = next(svc for svc in services if svc.name == "api")

    await _accept(
        client,
        project_id=str(project.id),
        service_id=str(api_svc.id),
        vulnerability_id=str(vuln.id),
    )

    active = (await client.get("/api/v1/vulnerabilities/active")).json()["items"]
    assert len(active) == 1
    assert active[0]["services"] == ["worker"]


@pytest.mark.asyncio
async def test_snapshot_today_excludes_accepted_after_acceptance(client, db_session):
    project, _ = await _seed_open(db_session, name="snap-accept", cve_id="CVE-2026-7012")
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7012")
        )
    ).scalar_one()

    await do_snapshot_metrics(db_session)
    row = (
        await db_session.execute(
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.snapshot_date == date.today())
        )
    ).scalar_one()
    assert row.critical_count == 1

    await _accept(client, project_id=str(project.id), vulnerability_id=str(vuln.id))
    await do_snapshot_metrics(db_session)
    # do_snapshot_metrics commits inside; the already-loaded snapshot row is
    # stale in the identity map (expire_on_commit=False), so reload it.
    await db_session.refresh(row)
    assert row.critical_count == 0


@pytest.mark.asyncio
async def test_snapshot_historical_still_counts_vuln_accepted_later(client, db_session):
    project, _ = await _seed_open(db_session, name="snap-hist-accept", cve_id="CVE-2026-7013")
    vuln = (
        await db_session.execute(
            select(Vulnerability).where(Vulnerability.cve_id == "CVE-2026-7013")
        )
    ).scalar_one()

    # The finding was detected two days ago and is accepted only today.
    yesterday = date.today() - timedelta(days=1)
    two_days_ago = datetime.now(UTC) - timedelta(days=2)
    link = (
        await db_session.execute(
            select(SBOMVulnerability).where(SBOMVulnerability.vulnerability_id == vuln.id)
        )
    ).scalar_one()
    link.detected_at = two_days_ago
    await db_session.commit()

    await _accept(client, project_id=str(project.id), vulnerability_id=str(vuln.id))

    await do_snapshot_metrics(db_session, snapshot_date=yesterday.isoformat())
    row = (
        await db_session.execute(
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.snapshot_date == yesterday)
        )
    ).scalar_one()
    assert row.critical_count == 1

    await do_snapshot_metrics(db_session, snapshot_date=date.today().isoformat())
    row = (
        await db_session.execute(
            select(VulnerabilitySnapshot).where(VulnerabilitySnapshot.snapshot_date == date.today())
        )
    ).scalar_one()
    assert row.critical_count == 0
