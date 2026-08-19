import pytest

from tests.helpers import _add_vuln, _service_id, _upload


@pytest.mark.asyncio
async def test_sboms_page(client):
    resp = await client.get("/sboms")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_sboms_page_pagination(client):
    resp = await client.get("/sboms?page=1&per_page=10&sort=created_at&order=desc")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_sboms_page_filters(client, db_session):
    proj = await client.post("/api/v1/projects", json={"name": "sboms-page"})
    pid = proj.json()["id"]
    sbom_id = await _upload(client, pid, "a", "1.0", service_name="svc")
    await _add_vuln(db_session, sbom_id, "CVE-2026-3007")
    svc_id = await _service_id(client, pid)

    resp = await client.get(f"/sboms?project_id={pid}")
    assert resp.status_code == 200

    resp = await client.get(f"/sboms?service_id={svc_id}")
    assert resp.status_code == 200

    resp = await client.get("/sboms?order=asc")
    assert resp.status_code == 200

    resp = await client.get("/sboms?page=2&per_page=1")
    assert resp.status_code == 200

    resp = await client.get("/sboms", headers={"HX-Request": "true"})
    assert resp.status_code == 200
