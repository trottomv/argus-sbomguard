"""Tests for the FastAPI app lifespan and health endpoint."""

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from models.auth import User


@pytest.mark.asyncio
async def test_lifespan_starts_and_stops_grpc(db_session, monkeypatch):
    import main

    factory = async_sessionmaker(db_session.bind, expire_on_commit=False)
    monkeypatch.setattr(main, "async_session_factory", factory)

    grpc_server = AsyncMock()
    grpc_server.stop = AsyncMock(return_value=None)
    with patch("main.start_grpc_server", new_callable=AsyncMock, return_value=grpc_server) as start:
        async with main.lifespan(main.app):
            start.assert_awaited_once()
        grpc_server.stop.assert_awaited_once_with(5)


@pytest.mark.asyncio
async def test_lifespan_seeds_admin_user(db_session, monkeypatch):
    from sqlalchemy import select

    import main

    factory = async_sessionmaker(db_session.bind, expire_on_commit=False)
    monkeypatch.setattr(main, "async_session_factory", factory)
    monkeypatch.setattr(main, "start_grpc_server", AsyncMock())

    async with main.lifespan(main.app):
        pass

    rows = (
        (
            await db_session.execute(
                select(User).where(User.email == "admin@argus.local", User.is_admin.is_(True))
            )
        )
        .scalars()
        .all()
    )
    assert rows
