# Argus SBOM Guard

Centralized SBOM management platform for tracking software supply chain security.
On-prem, deploy anywhere.

## Quick Start

```bash
cp .env.example .env
docker compose up -d
docker compose exec app alembic upgrade head
```

Open [http://localhost:8000](http://localhost:8000), log in with `admin@argus.local`,
and grab the one-time code from [Mailpit](http://localhost:8025) (dev only).

## Core Features

- **SBOM Management** — Upload, store, and diff CycloneDX & SPDX SBOMs
- **Vulnerability Scanning** — Automatic scanning via Grype + OSV API
- **Alerting** — Slack and email alerts for new vulnerabilities
- **REST API + gRPC** — Full API with key-based authentication
- **Dashboard** — Real-time vulnerability trends and per-project metrics

## Architecture at a Glance

```
projects → services → sboms → dependencies
vulnerabilities ──M:N── sboms (via sbom_vulnerabilities)
vulnerability_snapshots (daily per-project metrics)
alert_configs → notifications
users → api_keys / login_tokens
```

| Layer | Technology |
|-------|------------|
| Backend | Python 3.12 + FastAPI + Celery + RabbitMQ |
| Frontend | HTMX + Jinja2 + Alpine.js + DaisyUI 5 + Tailwind CSS v4 |
| Database | PostgreSQL 18 + asyncpg |
| Vuln Scanner | Grype + OSV API |
| Auth | Passwordless email login + API keys |

## Who Is This For?

- **Platform / SRE teams** tracking dependencies across microservices
- **Security engineers** monitoring vulnerability exposure over time
- **Open source maintainers** generating and managing SBOMs
- **Compliance teams** that need SBOM history and audit trails
