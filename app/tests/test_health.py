import pytest

import main


@pytest.mark.asyncio
async def test_healthz(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "argus-sbomguard"
    assert "version" in data
    assert "git_sha" in data
    assert "build_date" in data
    assert "source_url" in data
    assert "environment" in data


@pytest.mark.asyncio
async def test_version_endpoint(client):
    resp = await client.get("/version")
    assert resp.status_code == 200
    data = resp.json()
    assert data == {
        "service": "argus-sbomguard",
        "version": main.settings.app_version,
        "git_sha": main.settings.build_git_sha,
        "build_date": main.settings.build_date,
        "source_url": main.settings.build_source_url,
        "build_env": main.settings.build_env,
        "environment": main.settings.app_env,
    }


@pytest.mark.asyncio
async def test_favicon(client):
    resp = await client.get("/favicon.ico")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/vnd.microsoft.icon"
    assert resp.content[:4] == b"\x00\x00\x01\x00"


@pytest.mark.asyncio
async def test_readyz_ok(client):
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["checks"] == {"database": "ok", "rabbitmq": "ok"}


@pytest.mark.asyncio
async def test_readyz_database_failure(client, monkeypatch):
    class FailingConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, *args, **kwargs):
            raise Exception("db down")

    class FailingEngine:
        def connect(self):
            return FailingConn()

    monkeypatch.setattr(main, "engine", FailingEngine())
    resp = await client.get("/readyz")
    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "error"
    assert data["checks"]["database"] == "error"
    assert data["checks"]["rabbitmq"] == "ok"


@pytest.mark.asyncio
async def test_readyz_rabbitmq_failure(client, monkeypatch):
    class OkConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, *args, **kwargs):
            return None

    class OkEngine:
        def connect(self):
            return OkConn()

    monkeypatch.setattr(main, "engine", OkEngine())

    def boom_connection(*args, **kwargs):
        raise OSError("rabbitmq down")

    monkeypatch.setattr(main.asyncio, "open_connection", boom_connection)
    resp = await client.get("/readyz")
    assert resp.status_code == 503
    data = resp.json()
    assert data["status"] == "error"
    assert data["checks"]["database"] == "ok"
    assert data["checks"]["rabbitmq"] == "error"


@pytest.mark.asyncio
async def test_readyz_database_timeout(client, monkeypatch):
    import asyncio as _asyncio

    class StalledConn:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, *args, **kwargs):
            await _asyncio.sleep(60)

    class StalledEngine:
        def connect(self):
            return StalledConn()

    monkeypatch.setattr(main, "engine", StalledEngine())
    monkeypatch.setattr(main.settings, "readiness_timeout_seconds", 0.001)
    resp = await client.get("/readyz")
    assert resp.status_code == 503
    data = resp.json()
    assert data["checks"]["database"] == "error"
