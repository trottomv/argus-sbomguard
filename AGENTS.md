# Argus SBOM Guard — Agent Guide

## Stack
- **Backend**: Python FastAPI + asyncpg + Celery + RabbitMQ
- **Frontend**: HTMX + Jinja2 + Alpine.js + DaisyUI 5 + Tailwind CSS v4 (SSR)
- **Database**: PostgreSQL 18 + JSONB
- **Deploy**: Docker Compose
- **Vuln Scanner**: Grype (via Celery) + OSV API
- **Email (dev)**: Mailpit on port 8025
- **Auth**: Passwordless email login + API keys for REST/gRPC

## Pre-commit & quality checks (MANDATORY before every commit)

```bash
# Run all checks
pre-commit run --all-files

# Run tests
docker compose exec app pytest -v

# Only commit if BOTH pass
```

If any hook fails, fix and re-run before committing. Never commit with failing checks.

## Project structure
```
argus-sbomguard/
├── docker-compose.development.yml   # dev entry point (include + override)
├── docker-compose.remote.yml        # remote entry point
├── docker-compose/
│   ├── app.yml                      # app + worker + scheduler
│   ├── mailpit.yml                  # mailpit (dev only)
│   ├── postgresql.yml               # postgres
│   └── rabbitmq.yml                 # rabbitmq
├── .env.example                  # copy to .env before running
├── AGENTS.md
├── justfile                      # shortcut commands
├── rabbitmq.conf
├── scripts/                      # utility scripts
├── app/
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── requirements/
│   │   ├── remote.txt            # compiled runtime deps with hashes
│   │   └── dev.txt               # compiled dev deps with hashes
│   ├── entrypoint.sh
│   ├── alembic.ini              # points to migrations/
│   ├── migrations/              # DB migrations (single 0001_initial_schema)
│   ├── pyproject.toml           # single source of truth for dependencies
│   ├── main.py                  # FastAPI entrypoint + lifespan
│   ├── config.py                # pydantic-settings (reads .env)
│   ├── database.py              # async engine + session factory
│   ├── celery_app.py            # Celery app config
│   ├── middleware/               # AuthMiddleware + API key dependency
│   ├── models/                  # SQLAlchemy ORM (14 tables)
│   ├── api/                     # FastAPI route handlers
│   ├── services/                # Business logic + Celery tasks
│   ├── templates/               # Jinja2 (HTMX pages + partials)
│   ├── static/                  # CSS + images
│   └── tests/                   # pytest + httpx
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

# Run all checks (lint + format + SAST + SCA)
pre-commit run --all-files

# Lint check
docker compose exec app ruff check app/

# Format check
docker compose exec app ruff format app/ --check

# SAST (bandit)
docker compose exec app bandit -c pyproject.toml -r app/

# SCA (pip-audit)
docker compose exec app pip-audit --require-hashes --disable-pip -r requirements/remote.txt

# Compile requirements with hashes (run after changing deps in pyproject.toml)
just compile-requirements

# Scan compose images with syft
just scan-all

# Pre-commit (install once)
pip install pre-commit && pre-commit install
```

## Key conventions
- **SBOM formats**: CycloneDX (JSON) primary; SPDX secondary.
- **Auth**: Passwordless email login for HTML UI. API keys (`X-API-Key` header) for REST/gRPC. gRPC metadata `api-key`. Session via signed cookie (no Starlette SessionMiddleware).
- **JSONB columns**: `sboms.raw_sbom`, `dependencies.metadata`.
- **Async everywhere**: `asyncpg` + SQLAlchemy async session. No sync DB access.
- **Migrations**: Single `0001_initial_schema.py`. Always via `alembic revision --autogenerate`.
- **Celery tasks**: Defined in `services/tasks.py` with `@celery_app.task(name="tasks.*")`.
- **HTMX routes**: Return `TemplateResponse` for pages. API under `/api/v1/`.
- **Buttons**: Primary CTAs use `btn-primary btn-lg` + gradient (`bg-gradient-to-r from-indigo-500 to-purple-600 border-0 text-white`). Destructive use `btn-error`. Modal buttons use solid colors (no gradient). Cancel buttons use `btn-outline`.
- **Cards**: Use `rounded-xl bg-ctp-mantle border border-ctp-surface0 p-6` (not DaisyUI card).
- **Template partials**: Reusable components in `app/templates/partials/`.

## Database — 14 tables
```
users → api_keys / login_tokens
projects → services → sboms → dependencies
vulnerabilities ──M:N (via sbom_vulnerabilities)── sboms
vulnerability_snapshots (daily per-project metrics)
alert_configs → notifications / pull_requests
```

## Services in docker-compose
| Service | Port | Purpose |
|---------|------|---------|
| app | 8000, 50051 | FastAPI + gRPC |
| postgres | 5432 | Database |
| rabbitmq | 5672, 15672 | Celery broker |
| mailpit | 1025, 8025 | Dev SMTP + UI |
| worker | — | Celery worker |
| scheduler | — | Celery beat |

## Testing
- `pytest` + `httpx.AsyncClient` in `tests/test_api.py`
- `pytest-asyncio` for async tests
- SQLite in-memory for tests (via `conftest.py`)
- 61 tests, all must pass before committing

## Gotchas
- `.env` required (copy from `.env.example`).
- `COMPOSE_FILE` must be set in `.env` (default: `docker-compose.development.yml`), as there is no default `docker-compose.yml`.
- DB tables created via `alembic upgrade head` (not auto-create).
- `worker` and `scheduler` run the same image as `app`.
- Mailpit catches all dev emails at `localhost:8025`.
- Migration file may be root-owned after Docker generation — `chown` before committing.
- API key endpoints accept both session cookie (web UI) and `X-API-Key` header (API).
- **PostgreSQL upgrade from 16 to 18**: existing `postgres_data` volumes must be recreated (`docker compose down -v`) or migrated via dump/restore.
