import pytest
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from models.project import Project


@pytest.mark.asyncio
async def test_slug_generated_from_name(db_session):
    project = Project(name="Argus SBOM Guard")
    db_session.add(project)
    await db_session.flush()
    await db_session.refresh(project)

    assert project.slug == "argus-sbom-guard"


@pytest.mark.asyncio
async def test_slug_normalizes_separators(db_session):
    project = Project(name="api_gateway.v2")
    db_session.add(project)
    await db_session.flush()
    await db_session.refresh(project)

    assert project.slug == "api-gateway-v2"


@pytest.mark.asyncio
async def test_slug_preserves_unicode_letters(db_session):
    project = Project(name="Mio Progetto")
    db_session.add(project)
    await db_session.flush()
    await db_session.refresh(project)

    assert project.slug == "mio-progetto"


@pytest.mark.asyncio
async def test_slug_preserves_cjk_chars(db_session):
    project = Project(name="日本語")
    db_session.add(project)
    await db_session.flush()
    await db_session.refresh(project)

    assert project.slug == "日本語"


@pytest.mark.asyncio
async def test_slug_is_read_only(db_session):
    project = Project(name="Read Only")
    db_session.add(project)
    await db_session.flush()
    await db_session.refresh(project)
    assert project.slug == "read-only"

    project.slug = "forced-slug"
    with pytest.raises((OperationalError, ProgrammingError)):
        await db_session.flush()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_slug_recomputed_on_rename(db_session):
    project = Project(name="Old Name")
    db_session.add(project)
    await db_session.flush()
    await db_session.refresh(project)
    assert project.slug == "old-name"

    project.name = "New Name"
    await db_session.flush()
    await db_session.refresh(project)

    assert project.slug == "new-name"


@pytest.mark.asyncio
async def test_slug_collision_raises_integrity_error(db_session):
    db_session.add(Project(name="Foo Bar"))
    await db_session.flush()

    db_session.add(Project(name="foo_bar"))
    with pytest.raises(IntegrityError):
        await db_session.flush()
    await db_session.rollback()
