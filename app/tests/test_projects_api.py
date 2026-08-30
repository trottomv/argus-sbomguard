import json

import pytest

from tests.helpers import SAMPLE_CYCLONEDX


@pytest.mark.asyncio
async def test_create_project(client):
    resp = await client.post(
        "/api/v1/projects",
        json={"name": "test-service", "description": "A test project"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "test-service"
    assert "id" in data
    assert data["description"] == "A test project"


@pytest.mark.asyncio
async def test_list_projects(client):
    await client.post("/api/v1/projects", json={"name": "s1"})
    await client.post("/api/v1/projects", json={"name": "s2"})

    resp = await client.get("/api/v1/projects")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "per_page" in data
    assert "total_pages" in data
    assert len(data["items"]) >= 2


@pytest.mark.asyncio
async def test_list_projects_pagination(client):
    await client.post("/api/v1/projects", json={"name": "p1"})
    await client.post("/api/v1/projects", json={"name": "p2"})
    await client.post("/api/v1/projects", json={"name": "p3"})

    resp = await client.get("/api/v1/projects?page=1&per_page=2")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["total"] >= 3
    assert data["total_pages"] >= 2
    assert data["page"] == 1
    assert data["per_page"] == 2

    resp2 = await client.get("/api/v1/projects?page=2&per_page=2")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["items"]) >= 1
    assert data2["page"] == 2


@pytest.mark.asyncio
async def test_create_duplicate_project(client):
    await client.post("/api/v1/projects", json={"name": "dup"})
    resp = await client.post("/api/v1/projects", json={"name": "dup"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_create_project_slug_generated(client):
    resp = await client.post("/api/v1/projects", json={"name": "My New Service"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["slug"] == "my-new-service"
    assert data["id"] != data["slug"]


@pytest.mark.asyncio
async def test_create_project_slug_collision_409(client):
    await client.post("/api/v1/projects", json={"name": "Foo Bar"})
    resp = await client.post("/api/v1/projects", json={"name": "foo_bar"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_project_slug_in_list_and_get(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "slug-lookup"})
    pid = create_resp.json()["id"]
    assert create_resp.json()["slug"] == "slug-lookup"

    get_resp = await client.get(f"/api/v1/projects/{pid}")
    assert get_resp.status_code == 200
    assert get_resp.json()["slug"] == "slug-lookup"

    list_resp = await client.get("/api/v1/projects")
    items = list_resp.json()["items"]
    assert any(item["slug"] == "slug-lookup" for item in items)


@pytest.mark.asyncio
async def test_create_project_non_ascii_name(client):
    resp = await client.post("/api/v1/projects", json={"name": "Mio Progetto"})
    assert resp.status_code == 201
    assert resp.json()["slug"] == "mio-progetto"


@pytest.mark.asyncio
async def test_create_project_unicode_name(client):
    resp = await client.post("/api/v1/projects", json={"name": "日本語"})
    assert resp.status_code == 201
    assert resp.json()["name"] == "日本語"


@pytest.mark.asyncio
async def test_create_project_requires_alphanumeric(client):
    resp = await client.post("/api/v1/projects", json={"name": "!!!"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_project_strips_nul_bytes(client):
    resp = await client.post("/api/v1/projects", json={"name": "nul\x00test"})
    assert resp.status_code == 201
    assert resp.json()["name"] == "nultest"


@pytest.mark.asyncio
async def test_create_project_string_body_rejected(client):
    resp = await client.post("/api/v1/projects", json="not-an-object")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_project_platform_too_long_rejected(client):
    resp = await client.post("/api/v1/projects", json={"name": "ok", "platform": "p" * 51})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_project_repo_url_too_long_rejected(client):
    resp = await client.post("/api/v1/projects", json={"name": "ok", "repo_url": "u" * 1025})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_project_name_too_long_rejected(client):
    resp = await client.post("/api/v1/projects", json={"name": "n" * 256})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_project_non_string_value_passthrough(client):
    resp = await client.post("/api/v1/projects", json={"name": "ok", "description": 123})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_project_list_value_stripped(client):
    resp = await client.post("/api/v1/projects", json={"name": "ok", "description": ["a", "b"]})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_rename_project_requires_alphanumeric(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "renamable"})
    pid = create_resp.json()["id"]

    resp = await client.patch(f"/api/v1/projects/{pid}", json={"name": "###"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_rename_project_name_null_noop(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "null-name"})
    pid = create_resp.json()["id"]

    resp = await client.patch(f"/api/v1/projects/{pid}", json={"name": None})
    assert resp.status_code == 200
    assert resp.json()["name"] == "null-name"


def test_is_slug_conflict_helper():
    from sqlalchemy.exc import IntegrityError

    from api.v1.projects import _is_slug_conflict

    class SlugOrig:
        constraint_name = "ix_projects_slug"

    class NameOrig:
        constraint_name = "ix_projects_name"

    assert _is_slug_conflict(IntegrityError("stmt", {}, SlugOrig()))
    assert not _is_slug_conflict(IntegrityError("stmt", {}, NameOrig()))


@pytest.mark.asyncio
async def test_get_project(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "get-me"})
    pid = create_resp.json()["id"]

    resp = await client.get(f"/api/v1/projects/{pid}")
    assert resp.status_code == 200
    assert resp.json()["name"] == "get-me"


@pytest.mark.asyncio
async def test_get_project_not_found(client):
    resp = await client.get("/api/v1/projects/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_project(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "to-delete"})
    pid = create_resp.json()["id"]

    delete_resp = await client.delete(f"/api/v1/projects/{pid}")
    assert delete_resp.status_code == 204

    get_resp = await client.get(f"/api/v1/projects/{pid}")
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_project_cascades_snapshots(client):
    create_resp = await client.post("/api/v1/projects", json={"name": "cascade-test"})
    pid = create_resp.json()["id"]

    await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "version": "v1"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )

    delete_resp = await client.delete(f"/api/v1/projects/{pid}")
    assert delete_resp.status_code == 204

    get_resp = await client.get(f"/api/v1/projects/{pid}")
    assert get_resp.status_code == 404


@pytest.mark.asyncio
async def test_project_history_empty(client):
    resp = await client.post("/api/v1/projects", json={"name": "history-test"})
    pid = resp.json()["id"]

    resp = await client.get(f"/api/v1/projects/{pid}/history")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert data["items"] == []
    assert data["total"] == 0
    assert "page" in data


@pytest.mark.asyncio
async def test_project_history_with_sboms(client):
    proj = await client.post("/api/v1/projects", json={"name": "history-sboms"})
    pid = proj.json()["id"]

    await client.post(
        "/api/v1/sboms/upload",
        data={"project_id": pid, "version": "v1"},
        files={"file": ("sbom.json", json.dumps(SAMPLE_CYCLONEDX), "application/json")},
    )

    resp = await client.get(f"/api/v1/projects/{pid}/history")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["total"] == 1


@pytest.mark.asyncio
async def test_project_history_pagination(client):
    proj = await client.post("/api/v1/projects", json={"name": "hist-pag"})
    pid = proj.json()["id"]

    base = {
        "bomFormat": "CycloneDX",
        "components": [{"name": "lodash", "version": "4.17.20"}],
    }

    for version in ["v1", "v2", "v3"]:
        content = dict(base)
        content["version"] = version  # different version field in SBOM -> different SHA256
        await client.post(
            "/api/v1/sboms/upload",
            data={"project_id": pid, "version": version},
            files={"file": ("sbom.json", json.dumps(content), "application/json")},
        )

    resp = await client.get(f"/api/v1/projects/{pid}/history?page=1&per_page=2")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["total"] >= 3
    assert data["total_pages"] >= 2


@pytest.mark.asyncio
async def test_project_history_not_found(client):
    resp = await client.get("/api/v1/projects/00000000-0000-0000-0000-000000000000/history")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_project_history_huge_page(client):
    create = await client.post("/api/v1/projects", json={"name": "huge-page"})
    pid = create.json()["id"]
    resp = await client.get(f"/api/v1/projects/{pid}/history?page={2**63}")
    assert resp.status_code == 200
    assert resp.json()["page"] == 2**63
    assert resp.json()["items"] == []


@pytest.mark.asyncio
async def test_delete_project_not_found(client):
    resp = await client.delete("/api/v1/projects/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_project(client):
    create = await client.post("/api/v1/projects", json={"name": "update-me"})
    pid = create.json()["id"]

    resp = await client.patch(
        f"/api/v1/projects/{pid}",
        json={
            "name": "updated",
            "description": "desc",
            "repo_url": "https://example.com",
            "platform": "github",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "updated"
    assert data["slug"] == "updated"
    assert data["description"] == "desc"
    assert data["repo_url"] == "https://example.com"
    assert data["platform"] == "github"


@pytest.mark.asyncio
async def test_update_project_platform_too_long_rejected(client):
    create = await client.post("/api/v1/projects", json={"name": "update-len"})
    pid = create.json()["id"]

    resp = await client.patch(f"/api/v1/projects/{pid}", json={"platform": "p" * 51})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_update_project_not_found(client):
    resp = await client.patch(
        "/api/v1/projects/00000000-0000-0000-0000-000000000000",
        json={"name": "x"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_update_project_name_conflict(client):
    await client.post("/api/v1/projects", json={"name": "taken"})
    create = await client.post("/api/v1/projects", json={"name": "other"})
    pid = create.json()["id"]

    resp = await client.patch(f"/api/v1/projects/{pid}", json={"name": "taken"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_update_project_slug_collision_409(client):
    await client.post("/api/v1/projects", json={"name": "foo_bar"})
    create = await client.post("/api/v1/projects", json={"name": "a"})
    pid = create.json()["id"]

    resp = await client.patch(f"/api/v1/projects/{pid}", json={"name": "Foo Bar"})
    assert resp.status_code == 409
