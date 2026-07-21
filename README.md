# Argus SBOM Guard

Centralized SBOM management platform for system administrators. On-prem, deploy anywhere.

## Quick Start

```bash
cp .env.example .env
docker compose up -d
docker compose exec app alembic upgrade head
```

Open http://localhost:8000

## Development

```bash
# Install pre-commit hooks
pip install pre-commit && pre-commit install

# Lint
docker compose exec app ruff check app/

# Format
docker compose exec app ruff format app/

# SAST (security scan)
docker compose exec app bandit -c pyproject.toml -r app/

# SCA (dependency audit)
docker compose exec app pip-audit --strict -r requirements.txt

# Tests
docker compose exec app pytest -v
```

## Services

| Service | Port | URL |
|---------|------|-----|
| App | 8000 | http://localhost:8000 |
| RabbitMQ | 15672 | http://localhost:15672 |
| Grafana | 3000 | http://localhost:3000 |

## API

- `POST /api/v1/projects` — Create project
- `POST /api/v1/sboms/upload` — Upload SBOM (CycloneDX / SPDX JSON)
- `GET /api/v1/sboms/{id}` — SBOM detail with dependencies + vulnerabilities
- `GET /api/v1/sboms/{id}/diff/{other_id}` — Diff two SBOM versions
- `GET /api/v1/vulnerabilities/active` — Active vulnerabilities
- `POST /api/v1/alerts` — Configure alert rules

## License

AGPL v3
