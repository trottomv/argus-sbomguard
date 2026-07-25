<p align="center">
  <img src="app/static/img/argus-sbomguard.png" alt="Argus SBOM Guard" width="200">
</p>

<p align="center">
  <a href="https://github.com/trottomv/argus-sbomguard/releases"><img alt="Version" src="https://img.shields.io/badge/version-0.0.1--beta-orange?style=flat-square"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-AGPLv3-blue?style=flat-square"></a>
</p>

# Argus SBOM Guard

**Open-source SBOM-based vulnerability management platform.**

Import CycloneDX/SPDX SBOMs, scan dependencies with Grype and OSV, track vulnerabilities over time, and monitor your software supply chain risk.

*Centralized SBOM management. On-prem, deploy anywhere.*

> **Beta** — Argus SBOM Guard is in active development. APIs and features may change.

## Why Argus?

Software teams generate thousands of SBOMs, but an SBOM alone does not tell you:

- Which vulnerabilities affect your projects
- Whether your security posture is improving
- Which services are at risk
- When new vulnerabilities appear

Argus turns SBOMs into actionable security intelligence.

## Features

- **SBOM ingestion** — Upload and store CycloneDX JSON and SPDX JSON
- **Vulnerability scanning** — Automatic analysis via Grype and OSV API
- **Vulnerability tracking** — CVE status, severity, open/fixed, historical trends
- **Supply chain visibility** — Projects, services, dependencies, version history
- **SBOM diffing** — Compare dependency changes between versions
- **Alerting** — Slack and email notifications for new vulnerabilities
- **Integrations** — REST API and gRPC for programmatic SBOM upload
- **Dashboard** — Real-time trends and per-project vulnerability metrics

## Quick Start

```bash
cp .env.example .env
docker compose up -d
docker compose exec app alembic upgrade head
```

Open [http://localhost:8000](http://localhost:8000) → login with `admin@argus.local` (default), one-time code sent to [Mailpit](http://localhost:8025).

## Who Is Argus For?

**Teams that need self-hosted SBOM-based vulnerability management.**

- DevSecOps teams managing supply chain risk
- Organizations integrating SBOM generation into CI/CD
- Security engineers tracking vulnerability exposure over time
- SRE / Platform teams monitoring dependencies across services

**Argus is not:**

- A replacement for SBOM generators (use [Syft](https://github.com/anchore/syft))
- A container image scanner
- A vulnerability database

## Architecture

```
projects → services → sboms → dependencies
vulnerabilities ──M:N── sboms (via sbom_vulnerabilities)
vulnerability_snapshots (daily per-project metrics)
alert_configs → notifications
users → api_keys / login_tokens
```

| Layer | Technology |
|-------|------------|
| Backend | Python + FastAPI + Celery + RabbitMQ |
| Frontend | HTMX + Jinja2 + Alpine.js + DaisyUI 5 + Tailwind CSS v4 |
| Database | PostgreSQL 18 |
| Scanning | Grype CLI + OSV API |
| Auth | Passwordless email + API keys |

## Services

| Service | Port | URL |
|---------|------|-----|
| App (FastAPI) | 8000 | http://localhost:8000 |
| gRPC | 50051 | — |
| PostgreSQL | 5432 | — |
| RabbitMQ | 5672, 15672 | http://localhost:15672 |
| Mailpit (dev) | 1025, 8025 | http://localhost:8025 |

## API

OpenAPI docs at [http://localhost:8000/api/docs](http://localhost:8000/api/docs).

Key endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/projects` | Create project |
| `POST` | `/api/v1/sboms/upload` | Upload SBOM (CycloneDX / SPDX) |
| `GET` | `/api/v1/sboms/{id}/diff/{other_id}` | Diff two SBOM versions |
| `GET` | `/api/v1/vulnerabilities/active` | List open vulnerabilities |
| `POST` | `/api/v1/api-keys` | Generate API key |
| `POST` | `/api/v1/alerts` | Configure alert rules |

Authentication via `X-API-Key` header (REST) or `api-key` metadata (gRPC).

## Roadmap

- CI/CD integration examples
- Kubernetes deployment guides
- Advanced vulnerability workflows
- Additional notification integrations

## Development

```bash
cp .env.example .env
docker compose up -d
docker compose exec app alembic upgrade head
docker compose exec app pytest -v
```

Full contributing guide at [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

Full documentation is available at [https://trottomv.github.io/argus-sbomguard](https://trottomv.github.io/argus-sbomguard) or locally via `mkdocs serve`.
