# Argus SBOM Guard

Centralized SBOM management platform. On-prem, deploy anywhere.

## Quick Start

```bash
cp .env.example .env
docker compose up -d
docker compose exec app alembic upgrade head
```

Open http://localhost:8000 → login with email (admin@argus.local by default), code sent to Mailpit at http://localhost:8025.

## Authentication

- **Web UI**: passwordless login via email code (Mailpit in dev, SMTP in prod)
- **REST API / gRPC**: API keys managed from Settings page, passed via `X-API-Key` header
- **Session**: signed cookie, 24h expiry by default

## Services

| Service | Port | URL |
|---------|------|-----|
| App | 8000 | http://localhost:8000 |
| gRPC | 50051 | — |
| RabbitMQ | 15672 | http://localhost:15672 |
| Mailpit (dev) | 8025 | http://localhost:8025 |
| Postgres | 5432 | — |

## API

OpenAPI docs at http://localhost:8000/docs.

Key endpoints:
- `POST /api/v1/projects` — Create project
- `PATCH /api/v1/projects/{id}` — Update project
- `POST /api/v1/sboms/upload` — Upload SBOM (CycloneDX / SPDX JSON)
- `GET /api/v1/sboms/{id}/download` — Download raw SBOM
- `GET /api/v1/sboms/{id}/diff/{other_id}` — Diff two SBOM versions
- `POST /api/v1/api-keys` — Generate API key
- `POST /api/v1/alerts` — Configure alert rules

## Development

```bash
# Install pre-commit hooks
pip install pre-commit && pre-commit install

# Run all checks
pre-commit run --all-files

# Lint / Format
docker compose exec app ruff check app/
docker compose exec app ruff format app/

# SAST (security scan)
docker compose exec app bandit -c pyproject.toml -r app/

# SCA (dependency audit)
docker compose exec app pip-audit --strict -r requirements.txt

# Tests
docker compose exec app pytest -v

# Single test
docker compose exec app pytest tests/test_api.py -v

# Scan all compose images with syft
just scan-all
```

## Architecture

```
projects → services → sboms → dependencies
vulnerabilities ──M:N── sboms (via sbom_vulnerabilities)
vulnerability_snapshots (daily per-project metrics)
alert_configs → notifications
users → api_keys / login_tokens
```

- **Backend**: Python FastAPI + asyncpg + Celery + RabbitMQ
- **Frontend**: HTMX + Jinja2 + Alpine.js + DaisyUI 5 + Tailwind CSS v4 (SSR)
- **Database**: PostgreSQL 16
- **Vuln Scanner**: Grype (via Celery task) + OSV API
- **gRPC**: SBOM upload via `sbom.proto` on port 50051

## License

AGPL v3
