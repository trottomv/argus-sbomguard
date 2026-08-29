from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select

from config import settings
from models.project import Project
from models.sbom import SBOM, Dependency, SBOMFormat
from models.service import Service
from models.vulnerability import VulnerabilitySnapshot
from services.retention import do_prune_old_data, prune_sboms, prune_snapshots


def _sbom(
    project_id,
    *,
    service_id=None,
    created_at=None,
    uploaded_at=None,
    sha256,
    version="v1",
):
    created = created_at or datetime.now(UTC)
    return SBOM(
        project_id=project_id,
        service_id=service_id,
        version=version,
        format=SBOMFormat.CYCLONEDX,
        raw_sbom={"bomFormat": "CycloneDX"},
        sha256=sha256,
        created_at=created,
        uploaded_at=uploaded_at or created,
    )


@pytest.mark.asyncio
async def test_prune_snapshots_removes_expired(db_session):
    old_date = date.today() - timedelta(days=settings.snapshot_retention_days)
    boundary = date.today() - timedelta(days=settings.snapshot_retention_days - 1)
    db_session.add_all(
        [
            VulnerabilitySnapshot(project_id=None, snapshot_date=old_date, critical_count=3),
            VulnerabilitySnapshot(project_id=None, snapshot_date=boundary, critical_count=1),
            VulnerabilitySnapshot(project_id=None, snapshot_date=date.today(), critical_count=5),
        ]
    )
    await db_session.commit()

    await prune_snapshots(db_session)

    dates = (await db_session.execute(select(VulnerabilitySnapshot.snapshot_date))).scalars().all()
    assert old_date not in dates
    assert boundary in dates
    assert date.today() in dates


@pytest.mark.asyncio
async def test_prune_sboms_keeps_latest_per_service(db_session):
    project = Project(name="retention-svc")
    db_session.add(project)
    await db_session.flush()
    service = Service(project_id=project.id, name="svc")
    db_session.add(service)
    await db_session.flush()

    old = datetime.now(UTC) - timedelta(days=settings.sbom_retention_days + 10)
    recent = datetime.now(UTC)

    older = _sbom(
        project.id, service_id=service.id, created_at=old - timedelta(days=5), sha256="a" * 64
    )
    latest_old = _sbom(project.id, service_id=service.id, created_at=old, sha256="b" * 64)
    recent_sbom = _sbom(project.id, service_id=service.id, created_at=recent, sha256="c" * 64)
    db_session.add_all([older, latest_old, recent_sbom])
    await db_session.commit()

    await prune_sboms(db_session)

    remaining = (await db_session.execute(select(SBOM.id))).scalars().all()
    assert older.id not in remaining
    assert latest_old.id not in remaining  # older than retention, not the latest
    assert recent_sbom.id in remaining  # latest per service survives


@pytest.mark.asyncio
async def test_prune_sboms_safety_net_keeps_single_old(db_session):
    project = Project(name="retention-safety")
    db_session.add(project)
    await db_session.flush()
    service = Service(project_id=project.id, name="svc")
    db_session.add(service)
    await db_session.flush()

    old = datetime.now(UTC) - timedelta(days=settings.sbom_retention_days + 10)
    only_old = _sbom(project.id, service_id=service.id, created_at=old, sha256="g" * 64)
    db_session.add(only_old)
    await db_session.commit()

    await prune_sboms(db_session)

    remaining = (await db_session.execute(select(SBOM.id))).scalars().all()
    assert only_old.id in remaining  # safety net: at least one SBOM per service


@pytest.mark.asyncio
async def test_prune_sboms_removes_dependencies_of_deleted(db_session):
    project = Project(name="retention-deps")
    db_session.add(project)
    await db_session.flush()
    service = Service(project_id=project.id, name="svc")
    db_session.add(service)
    await db_session.flush()

    old = datetime.now(UTC) - timedelta(days=settings.sbom_retention_days + 10)
    older = _sbom(
        project.id, service_id=service.id, created_at=old - timedelta(days=5), sha256="d" * 64
    )
    latest_old = _sbom(project.id, service_id=service.id, created_at=old, sha256="e" * 64)
    db_session.add_all([older, latest_old])
    await db_session.flush()
    db_session.add_all(
        [
            Dependency(sbom_id=older.id, name="old-dep", version="1.0.0", purl="pkg:npm/old@1.0.0"),
            Dependency(
                sbom_id=latest_old.id, name="kept-dep", version="1.0.0", purl="pkg:npm/kept@1.0.0"
            ),
        ]
    )
    await db_session.commit()

    await prune_sboms(db_session)

    deps = (await db_session.execute(select(Dependency.name))).scalars().all()
    assert "old-dep" not in deps
    assert "kept-dep" in deps


@pytest.mark.asyncio
async def test_do_prune_old_data_sbom_retention_disabled(db_session, monkeypatch):
    project = Project(name="retention-disabled")
    db_session.add(project)
    await db_session.flush()
    service = Service(project_id=project.id, name="svc")
    db_session.add(service)
    await db_session.flush()

    old = datetime.now(UTC) - timedelta(days=settings.sbom_retention_days + 10)
    db_session.add(_sbom(project.id, service_id=service.id, created_at=old, sha256="f" * 64))
    old_snapshot = date.today() - timedelta(days=settings.snapshot_retention_days)
    db_session.add(
        VulnerabilitySnapshot(project_id=None, snapshot_date=old_snapshot, critical_count=3)
    )
    await db_session.commit()

    monkeypatch.setattr("services.retention.settings.sbom_retention_days", None)
    await do_prune_old_data(db_session)

    sbom_ids = (await db_session.execute(select(SBOM.id))).scalars().all()
    assert len(sbom_ids) == 1  # SBOM retention disabled → old SBOM kept
    dates = (await db_session.execute(select(VulnerabilitySnapshot.snapshot_date))).scalars().all()
    assert old_snapshot not in dates  # snapshot retention is always on
