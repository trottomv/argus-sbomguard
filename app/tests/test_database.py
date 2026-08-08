"""Tests for the async session dependency helper."""

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import database as database_module
from database import get_db
from models.auth import User


def _patch_factory(db_session, monkeypatch) -> None:
    factory = async_sessionmaker(db_session.bind, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(database_module, "async_session_factory", factory)


async def test_get_db_commits_on_success(db_session, monkeypatch):
    _patch_factory(db_session, monkeypatch)

    async for session in get_db():
        session.add(User(email="get-db-commit@example.com", is_admin=False))
        await session.flush()

    rows = (await db_session.execute(text("SELECT email FROM users"))).scalars().all()
    assert "get-db-commit@example.com" in rows


async def test_get_db_rolls_back_on_exception(db_session, monkeypatch):
    _patch_factory(db_session, monkeypatch)

    class _Boom(Exception):
        pass

    gen = get_db()
    await gen.__anext__()

    with pytest.raises(_Boom):
        await gen.athrow(_Boom())

    rows = (await db_session.execute(text("SELECT email FROM users"))).scalars().all()
    assert "get-db-rollback@example.com" not in rows
