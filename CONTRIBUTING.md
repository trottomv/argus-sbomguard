# Contributing to Argus SBOM Guard

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

# Install pre-commit hooks
pip install pre-commit && pre-commit install
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

This runs `pip-compile` with hashes for both `requirements/remote.txt` and `requirements/dev.txt`.

## Documentation

```bash
# Install docs dependencies
pip install mkdocs mkdocs-material "mkdocstrings[python]" mike

# Serve locally
mkdocs serve

# Publish a new version (after each release)
mike deploy --push --update-aliases v0.0.1-beta latest

# Set default version
mike set-default --push latest

# List published versions
mike list
```

## gRPC

Regenerate protobuf stubs after changes to `protos/sbom.proto`:

```bash
just proto
```

## CSS

The frontend uses Tailwind CSS v4 with DaisyUI 5. Rebuild CSS:

```bash
just css
```
