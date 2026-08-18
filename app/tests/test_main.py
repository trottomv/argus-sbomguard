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
    with (
        patch("main.start_grpc_server", new_callable=AsyncMock, return_value=grpc_server) as start,
        patch("main.shutdown_tracing") as shutdown,
    ):
        async with main.lifespan(main.app):
            start.assert_awaited_once()
        grpc_server.stop.assert_awaited_once_with(5)
        shutdown.assert_called_once()


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


@pytest.mark.asyncio
async def test_unhandled_exception_logged_and_returns_500(caplog):
    from httpx import ASGITransport, AsyncClient

    import main

    def boom():
        raise RuntimeError("kaboom")

    main.app.add_api_route("/api/v1/boom", boom, methods=["GET"])
    try:
        transport = ASGITransport(app=main.app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/api/v1/boom")
    finally:
        main.app.router.routes[:] = [
            route
            for route in main.app.router.routes
            if getattr(route, "path", None) != "/api/v1/boom"
        ]

    assert response.status_code == 500
    assert response.text == "Internal Server Error"
    assert response.headers["content-type"].startswith("text/plain")

    events = [record for record in caplog.records if getattr(record, "event", None) == "exception"]
    assert events
    record = events[0]
    assert record.levelname == "ERROR"
    assert record.type == "RuntimeError"
    assert record.getMessage() == "kaboom"
    assert "RuntimeError: kaboom" in record.traceback
    assert record.request_method == "GET"
    assert record.request_path == "/api/v1/boom"
    assert record.request_client
