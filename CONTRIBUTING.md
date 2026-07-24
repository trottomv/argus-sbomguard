# Contributing to Argus SBOM Guard

## Development Setup

```bash
git clone https://github.com/trottomv/argus-sbomguard.git
cd argus-sbomguard
cp .env.example .env
docker compose up -d
docker compose exec app alembic upgrade head
pip install pre-commit && pre-commit install
```

## Pre-commit & Quality Checks (mandatory before every commit)

```bash
# Run all checks
pre-commit run --all-files

# Run tests
docker compose exec app pytest -v

# Only commit if BOTH pass
```

If any hook fails, fix and re-run before committing. Never commit with failing checks.

## Key Conventions

- **Async everywhere**: `asyncpg` + SQLAlchemy async session. No sync DB access.
- **SBOM formats**: CycloneDX JSON primary; SPDX secondary.
- **JSONB columns**: `sboms.raw_sbom`, `dependencies.metadata`.
- **Migrations**: Single `0001_initial_schema.py`. Always via `alembic revision --autogenerate`.
- **Celery tasks**: Defined in `services/tasks.py` with `@celery_app.task(name="tasks.*")`.
- **HTMX routes**: Return `TemplateResponse` for pages. API under `/api/v1/`.
- **UI**: DaisyUI 5 + Tailwind CSS v4. Cards use `rounded-xl bg-ctp-mantle border border-ctp-surface0 p-6`.

## Commands

```bash
# Start everything
docker compose up -d

# Run DB migrations
docker compose exec app alembic upgrade head

# Run tests
docker compose exec app pytest -v

# Lint
docker compose exec app ruff check app/

# Format
docker compose exec app ruff format app/

# SAST
docker compose exec app bandit -c pyproject.toml -r app/

# SCA
docker compose exec app pip-audit --require-hashes --disable-pip -r requirements/remote.txt

# Compile requirements (after changing deps)
just compile-requirements

# Serve docs
mkdocs serve
```

## Documentation

Full docs at [docs/](docs/). Run locally with `mkdocs serve`.

## Test Setup

- `pytest` + `httpx.AsyncClient` + `pytest-asyncio`
- SQLite in-memory database for tests (configured in `conftest.py`)
