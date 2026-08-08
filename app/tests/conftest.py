import asyncio
from collections.abc import AsyncGenerator
from pathlib import Path

import alembic.command
import alembic.config
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from config import settings
from database import get_db
from main import app
from middleware.api_key import api_key_required
from models.auth import User
from models.base import Base

# Tests run against a dedicated PostgreSQL database (same server as the app,
# separate database) so the real schema — including the generated slug column
# and the public.slugify function — is exercised exactly as in production.
TEST_DATABASE_NAME = "argus_test"

_session_serializer = URLSafeTimedSerializer(settings.secret_key, salt="argus-session")


def _database_url(database: str) -> str:
    return (
        f"postgresql+asyncpg://{settings.postgres_user}:{settings.postgres_password}"
        f"@{settings.postgres_host}:{settings.postgres_port}/{database}"
    )


def _make_session_cookie(user_id: str) -> str:
    cookie = _session_serializer.dumps({"user_id": user_id})
    return cookie


async def _create_test_database() -> None:
    engine = create_async_engine(_database_url("postgres"), isolation_level="AUTOCOMMIT")
    async with engine.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{TEST_DATABASE_NAME}" WITH (FORCE)'))
        await conn.execute(text(f'CREATE DATABASE "{TEST_DATABASE_NAME}"'))
    await engine.dispose()


def _apply_migrations() -> None:
    alembic_ini = Path(__file__).resolve().parent.parent / "alembic.ini"
    config = alembic.config.Config(str(alembic_ini))
    config.set_main_option("sqlalchemy.url", _database_url(TEST_DATABASE_NAME))
    alembic.command.upgrade(config, "head")


@pytest.fixture(scope="session", autouse=True)
def _prepare_test_database():
    asyncio.run(_create_test_database())
    _apply_migrations()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine(_database_url(TEST_DATABASE_NAME), echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    user = User(email="admin@argus.local", is_admin=True)
    db_session.add(user)
    await db_session.commit()

    def override_get_db():
        yield db_session

    def override_api_key():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[api_key_required] = override_api_key

    transport = ASGITransport(app=app)
    cookies = {"argus_session": _make_session_cookie(str(user.id))}
    async with AsyncClient(transport=transport, base_url="http://test", cookies=cookies) as ac:
        yield ac

    app.dependency_overrides.clear()
