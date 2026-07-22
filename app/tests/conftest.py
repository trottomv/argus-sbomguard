import asyncio
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from config import settings
from database import get_db
from main import app
from middleware.api_key import api_key_required
from models.base import Base
from models.user import User

TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

_session_serializer = URLSafeTimedSerializer(settings.secret_key, salt="argus-session")


def _make_session_cookie(user_id: str) -> str:
    cookie = _session_serializer.dumps({"user_id": user_id})
    return cookie


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    user = User(email="admin@argus.local", is_admin=True)
    db_session.add(user)
    await db_session.commit()

    async def override_get_db():
        yield db_session

    async def override_api_key():
        return user

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[api_key_required] = override_api_key

    transport = ASGITransport(app=app)
    cookies = {"argus_session": _make_session_cookie(str(user.id))}
    async with AsyncClient(transport=transport, base_url="http://test", cookies=cookies) as ac:
        yield ac

    app.dependency_overrides.clear()
