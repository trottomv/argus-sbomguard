from unittest.mock import patch

import pytest


@pytest.mark.asyncio
async def test_dashboard_page(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_dashboard_home(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_refresh_snapshots(client):
    resp = await client.post("/refresh-snapshots")
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_refresh_snapshots_dispatches_task(client):
    with patch("api.pages.dashboard.snapshot_metrics") as mock_task:
        resp = await client.post("/refresh-snapshots")
    assert resp.status_code == 202
    mock_task.delay.assert_called_once_with()
