# Argus SBOM Guard — Agent Guide

## Stack
- **Backend**: Python FastAPI + asyncpg + Celery + RabbitMQ
- **Frontend**: HTMX + Jinja2 + Alpine.js (SSR, no JS framework)
- **Database**: PostgreSQL 16 + JSONB
- **Charts**: Grafana (datasource PostgreSQL, no Mimir)
- **Deploy**: Docker Compose
- **Vuln Scanner**: OSV API (`/v1/querybatch`)

## Project structure
```
argus-sbomguard/
├── docker-compose.yml            # postgres + rabbitmq + app + worker + grafana
├── .env.example                  # copy to .env before running
├── AGENTS.md
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── alembic/                  # DB migrations
│   └── app/
│       ├── main.py               # FastAPI entrypoint + lifespan
│       ├── config.py             # pydantic-settings (reads .env)
│       ├── database.py           # async engine + session factory
│       ├── celery_app.py         # Celery app config
│       ├── models/               # SQLAlchemy ORM (9 tables)
│       ├── api/                  # FastAPI route handlers
│       ├── services/             # Business logic + Celery tasks
│       ├── templates/            # Jinja2 (HTMX pages + partials)
│       └── static/               # CSS
```

## Commands
```bash
# Start everything
docker compose up -d

# Run DB migrations
docker compose exec app alembic upgrade head

# Create new migration (after model change)
docker compose exec app alembic revision --autogenerate -m "description"

# Run tests
docker compose exec app pytest -v

# Single test file
docker compose exec app pytest tests/test_api.py -v

# Watch app logs
docker compose logs -f app

# Tail worker logs
docker compose logs -f worker

# Enter app container
docker compose exec app bash

# Lint check (ruff)
docker compose exec app ruff check app/

# Lint fix
docker compose exec app ruff check app/ --fix

# Format check
docker compose exec app ruff format app/ --check

# Format
docker compose exec app ruff format app/

# SAST (bandit)
docker compose exec app bandit -c pyproject.toml -r app/

# SCA (pip-audit)
docker compose exec app pip-audit --strict -r requirements.txt

# Pre-commit (install once)
pip install pre-commit && pre-commit install

# Run all pre-commit hooks
pre-commit run --all-files
```

## Key conventions
- **SBOM formats**: CycloneDX (JSON) primary; SPDX secondary. Both validated via `store_sbom()` in `services/sbom_parser.py`.
- **JSONB columns**: `sboms.raw_sbom`, `dependencies.metadata`. All flexible/schemaless data goes here.
- **Async everywhere**: `asyncpg` + SQLAlchemy async session. No sync DB access.
- **Migrations**: Always via `alembic revision --autogenerate`, never raw SQL.
- **Celery tasks**: Defined in `services/tasks.py` with `@celery_app.task(name="tasks.*")`.
- **OSV API**: Batch query via `/v1/querybatch` in `services/vulnerability_scanner.py`.
- **HTMX routes**: Return `TemplateResponse` (not JSON) for pages under `/`, `GET`/`POST` API under `/api/v1/`.
- **No auth in MVP**: Single admin user. No auth middleware.

## Database — 9 tables
```
projects → sboms → dependencies
vulnerabilities ──M:N (via sbom_vulnerabilities)── sboms
vulnerability_snapshots (daily metrics per project)
alert_configs → notifications
pull_requests (renovate bot — Fase 2)
```

## Testing
- `pytest` + `httpx.AsyncClient` in `tests/test_api.py`
- `pytest-asyncio` for async tests
- SQLite in-memory for tests (via `conftest.py`)
- Integration tests need `docker compose up -d postgres rabbitmq`

## Gotchas
- `.env` required (copy from `.env.example`). Without it, defaults point to Docker services.
- DB tables created via `alembic upgrade head` (not auto-create).
- `worker` container runs the same image as `app` but with Celery command.
- Grafana provisioning is manual for now — connect datasource to `postgres` via UI.
- Renovate PR automation and AI agent not yet implemented (Fase 2).

## Grafana
- URL: `http://localhost:3000`
- Default credentials: `admin / admin`
- Datasource: PostgreSQL (`postgres:5432`, database `argus`)
- Recommended dashboards: vulnerability trends (use `vulnerability_snapshots` table)
