"""Frozen /api/v1 contract: the committed OpenAPI schema matches the app."""

import json
from pathlib import Path

import pytest

from api.constants import API_V1_PREFIX
from main import app

OPENAPI_PATH = Path(__file__).resolve().parents[2] / "docs" / "api" / "openapi.json"


def _api_paths(paths: dict) -> dict:
    return {path: ops for path, ops in paths.items() if path.startswith(f"{API_V1_PREFIX}/")}


@pytest.mark.asyncio
async def test_openapi_schema_served_at_public_path(client):
    resp = await client.get("/api/openapi.json")
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    assert f"{API_V1_PREFIX}/projects" in resp.json()["paths"]


def test_committed_openapi_schema_matches_app():
    live = app.openapi()
    committed = json.loads(OPENAPI_PATH.read_text())

    assert live["openapi"] == committed["openapi"]
    assert _api_paths(live["paths"]) == _api_paths(committed["paths"])
    assert live["components"] == committed["components"]
    assert live["info"]["title"] == committed["info"]["title"]
    assert live["info"]["version"] == committed["info"]["version"]


def test_openapi_schema_advertises_api_key_security():
    schema = app.openapi()
    schemes = schema["components"]["securitySchemes"]
    assert schemes["APIKeyHeader"] == {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    for path in _api_paths(schema["paths"]):
        for operation in schema["paths"][path].values():
            assert {"APIKeyHeader": []} in operation.get("security", [])


def test_openapi_schema_excludes_backoffice_pages():
    schema = app.openapi()
    paths = set(schema["paths"])
    for path in ("/", "/login", "/projects", "/sboms", "/settings", "/vulnerabilities"):
        assert path not in paths
    assert all(path.startswith(f"{API_V1_PREFIX}/") for path in paths - {"/healthz", "/readyz"})
