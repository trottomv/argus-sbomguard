# Testing

## Test Setup

Tests use pytest with `httpx.AsyncClient` and an in-memory SQLite database.

Run all tests:

```bash
docker compose exec app pytest -v
```

## Test Configuration

- `pytest-asyncio` with `asyncio_mode = "auto"` (set in `pyproject.toml`)
- `conftest.py` provides fixtures for test database, HTTP client, and auth
- Tests are in `app/tests/`

## Running Specific Tests

```bash
# Single file
docker compose exec app pytest tests/test_api.py -v

# Single test
docker compose exec app pytest tests/test_api.py::test_create_project -v

# With coverage
docker compose exec app pytest -v --cov=. --cov-report=term-missing
```

## Test Structure

| File | Tests |
|------|-------|
| `tests/test_api.py` | REST API endpoints (61 tests) |
| `tests/test_sbom_parser.py` | SBOM parsing (CycloneDX, SPDX) |

## Quality Gates

Before committing, the following must pass:

1. **Lint**: `ruff check app/`
2. **Format**: `ruff format app/ --check`
3. **SAST**: `bandit -c pyproject.toml -r app/`
4. **SCA**: `pip-audit --require-hashes --disable-pip -r requirements/remote.txt`
5. **Tests**: `pytest -v`

Use the shortcut:

```bash
pre-commit run --all-files
```

## CI / Pre-commit Hooks

Pre-commit is configured in `.pre-commit-config.yaml` and runs:

```yaml
- ruff (lint)
- ruff format (format)
- bandit (security)
- pip-audit (dependencies)
```

Install hooks once:

```bash
pip install pre-commit && pre-commit install
```
