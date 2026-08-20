import pytest


@pytest.mark.asyncio
async def test_create_alert(client):
    proj = await client.post("/api/v1/projects", json={"name": "alert-test"})
    pid = proj.json()["id"]

    resp = await client.post(
        "/api/v1/alert-rules",
        json={
            "project_id": pid,
            "severity_threshold": "critical",
            "notification_type": "email",
            "config": {"to": "admin@example.com"},
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["severity_threshold"] == "critical"
    assert data["notification_type"] == "email"
    assert data["enabled"] is True


@pytest.mark.asyncio
async def test_create_alert_project_not_found(client):
    resp = await client.post(
        "/api/v1/alert-rules",
        json={
            "project_id": "00000000-0000-0000-0000-000000000000",
            "severity_threshold": "high",
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_alerts(client):
    proj = await client.post("/api/v1/projects", json={"name": "alerts-list"})
    pid = proj.json()["id"]

    await client.post(
        "/api/v1/alert-rules",
        json={"project_id": pid, "notification_type": "slack"},
    )

    resp = await client.get("/api/v1/alert-rules")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert len(data["items"]) >= 1


@pytest.mark.asyncio
async def test_list_alerts_pagination(client):
    resp = await client.get("/api/v1/alert-rules?page=1&per_page=5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["page"] == 1
    assert data["per_page"] == 5


@pytest.mark.asyncio
async def test_delete_alert(client):
    proj = await client.post("/api/v1/projects", json={"name": "alerts-del"})
    pid = proj.json()["id"]

    create = await client.post(
        "/api/v1/alert-rules",
        json={"project_id": pid, "notification_type": "slack"},
    )
    aid = create.json()["id"]

    resp = await client.delete(f"/api/v1/alert-rules/{aid}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "deleted"


@pytest.mark.asyncio
async def test_delete_alert_not_found(client):
    resp = await client.delete("/api/v1/alert-rules/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_alert(client):
    proj = await client.post("/api/v1/projects", json={"name": "alert-update"})
    pid = proj.json()["id"]
    create = await client.post(
        "/api/v1/alert-rules",
        json={
            "project_id": pid,
            "severity_threshold": "high",
            "notification_type": "email",
            "enabled": True,
        },
    )
    aid = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/alert-rules/{aid}",
        json={
            "project_id": pid,
            "severity_threshold": "critical",
            "notification_type": "slack",
            "enabled": False,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "updated"


@pytest.mark.asyncio
async def test_update_alert_project_not_found(client):
    proj = await client.post("/api/v1/projects", json={"name": "alert-upd-pnf"})
    pid = proj.json()["id"]
    create = await client.post("/api/v1/alert-rules", json={"project_id": pid})
    aid = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/alert-rules/{aid}",
        json={"project_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_alert_not_found(client):
    resp = await client.patch(
        "/api/v1/alert-rules/00000000-0000-0000-0000-000000000000",
        json={"enabled": False},
    )
    assert resp.status_code == 404
