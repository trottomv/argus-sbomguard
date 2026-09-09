# Contributing to Argus SBOM Guard

## Prerequisites (host tools)

The runtime stack runs in Docker — only the tools below live on the host.
Install them from their official docs; don't install Docker via `apt`.

### Required

- Git
- Docker Engine ≥ 24
- Docker Compose v2 ≥ 2.20 (plugin `docker compose`, needs `include:`)
- Python ≥ 3.9 + pipx
- pre-commit (via pipx)
- just ≥ 1

### Optional (only if you use the recipe):

- bun ≥ 1 — `just css`
- uv ~= 0.12 — `just compile-requirements`
- syft — `just scan-all`
- jq — `just scan-all`, `just docs-openapi`
- cosign — `just verify-image`
- mkdocs / mike / mkdocstrings — docs (installed in `.docs-venv` by the `just docs-*` recipes that need them)

## Development Setup

```bash
# Clone
git clone https://github.com/trottomv/argus-sbomguard.git
cd argus-sbomguard

# Environment
cp .env.example .env

# Start services
docker compose up -d
docker compose exec app alembic upgrade head

# Install pre-commit hooks (once per clone)
pipx install pre-commit
pre-commit install
```

## Project Structure

```
argus-sbomguard/
├── docker-compose.development.yml   # dev entry point
├── docker-compose.remote.yml        # production entry point
├── docker-compose/                  # compose fragments
│   ├── app.yml
│   ├── mailpit.yml
│   ├── postgresql.yml
│   └── rabbitmq.yml
├── app/
│   ├── main.py                      # FastAPI entrypoint + lifespan
│   ├── config.py                    # pydantic-settings
│   ├── database.py                  # async engine + session factory
│   ├── celery_app.py                # Celery config
│   ├── middleware/                   # AuthMiddleware + API key dependency
│   ├── models/                      # SQLAlchemy ORM (14 tables)
│   ├── api/                         # FastAPI route handlers
│   ├── services/                    # Business logic + Celery tasks
│   ├── templates/                   # Jinja2 (HTMX pages + partials)
│   ├── static/                      # CSS + images
│   ├── migrations/                  # Alembic migrations
│   └── tests/                       # pytest
├── justfile                         # shortcut commands
├── mkdocs.yml                       # docs configuration
└── docs/                            # documentation source
```

## Quality Checks (mandatory before commit)

```bash
# Run all checks
pre-commit run --all-files

# Lint
docker compose exec app ruff check app/

# Format
docker compose exec app ruff format app/ --check

# SAST (security)
docker compose exec app bandit -c pyproject.toml -r app/

# SCA (dependency audit)
docker compose exec app pip-audit --require-hashes --disable-pip -r requirements/remote.txt

# Tests
docker compose exec app pytest -v
```

> All checks must pass before committing. Never commit with failing checks.

## Running Tests

```bash
# All tests
docker compose exec app pytest -v

# Single test file
docker compose exec app pytest tests/test_api.py -v

# With coverage
docker compose exec app pytest -v --cov=. --cov-report=term-missing
```

Tests use SQLite in-memory (configured in `conftest.py`) and `httpx.AsyncClient`.

## Code Conventions

- **Async everywhere**: `asyncpg` + SQLAlchemy async session. No sync DB access.
- **SBOM formats**: CycloneDX JSON primary; SPDX secondary.
- **Auth**: Passwordless email login for HTML UI. API keys for REST/gRPC.
- **JSONB columns**: `sboms.raw_sbom`, `dependencies.metadata`.
- **Migrations**: Via `alembic revision --autogenerate`. Single file `0001_initial_schema.py`.
- **Celery tasks**: Defined in `services/tasks.py` with `@celery_app.task(name="tasks.*")`.
- **HTMX routes**: Return `TemplateResponse`. API under `/api/v1/`.

## Database Migrations

```bash
# Apply pending migrations
docker compose exec app alembic upgrade head

# Create new migration (after model changes)
docker compose exec app alembic revision --autogenerate -m "description"
```

## Compiling Requirements

When you add or change dependencies in `pyproject.toml`:

```bash
just compile-requirements
```

This runs `uv pip compile` (uv's drop-in replacement for `pip-compile`) with hashes for both `requirements/remote.txt` and `requirements/dev.txt`. Requires [uv](https://docs.astral.sh/uv/) on the host.

## Documentation

Docs tooling (mkdocs, mkdocs-material, mkdocstrings, mike) is managed by the
`just docs-*` recipes, which install it in a local `.docs-venv`:

```bash
# Serve locally on :8001
just docs-serve

# Docs deploy is automatic via CI on tag (v*) and main branch — no manual steps needed.

# List published versions
just docs-list
```

## gRPC

Regenerate protobuf stubs after changes to `protos/sbom.proto`:

```bash
just proto
```

## CSS

The frontend uses Tailwind CSS v4 with DaisyUI 5. Rebuild CSS (requires
`bun` on the host — the compiled `dist.css` is gitignored and built into the
Docker image):

```bash
just css
```
