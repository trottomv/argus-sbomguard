# Architecture

## Overview

Argus SBOM Guard is an async-first Python web application for managing
Software Bill of Materials (SBOMs) and tracking vulnerabilities.

## Stack

| Component | Technology |
|-----------|------------|
| Web framework | FastAPI (uvicorn) |
| Database | PostgreSQL 18 |
| DB driver | asyncpg (async) |
| ORM | SQLAlchemy 2.0 (async session) |
| Task queue | Celery + RabbitMQ |
| Frontend | HTMX + Jinja2 + Alpine.js + DaisyUI 5 + Tailwind CSS v4 |
| Auth | Passwordless email login + signed cookies |
| gRPC | grpcio + protobuf |
| Vuln scanner | Grype CLI + OSV API |
| Observability | OpenTelemetry Collector (hostmetrics + OTLP) |

## Service Architecture

```
┌──────────────────────────────────────────────────┐
│                     Caddy (prod)                  │
│                  Reverse Proxy + WAF              │
└──────────────┬───────────────────────────────────┘
               │ :443
┌──────────────▼───────────────────────────────────┐
│                 FastAPI App :8000                 │
│  ┌─────────┐  ┌─────────┐  ┌──────────────────┐ │
│  │ Jinja2  │  │ REST    │  │ gRPC    :50051   │ │
│  │ Pages   │  │ /api/v1 │  │ sbom.proto       │ │
│  └─────────┘  └─────────┘  └──────────────────┘ │
│                     │                             │
│              AuthMiddleware                       │
│        (cookie + Bearer token)                     │
└──────────────┬───────────────────────────────────┘
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
┌───────┐ ┌───────┐ ┌──────────┐
│Postgre│ │Rabbit │ │ Mailpit  │
│SQL 18 │ │MQ     │ │ (dev)    │
└───────┘ └───┬───┘ └──────────┘
              │
    ┌─────────┼─────────┐
    ▼         ▼         ▼
┌────────┐ ┌──────┐ ┌───────────┐
│Worker  │ │Worker│ │Scheduler  │
│(Celery)│ │      │ │(Celery    │
│        │ │      │ │ Beat)     │
└────────┘ └──────┘ └───────────┘
```

The OTel Collector sits alongside the stack as the observability hub: it scrapes
`hostmetrics` from the host filesystem (`/hostfs`), exposes `GET /metrics`
through Caddy, receives optional OTLP traces from the app, and can forward to an
arbitrary OTLP backend. See [Observability](../guide/observability.md).

## Request Flow

### SBOM Upload & Scan

```
Client ──► POST /api/v1/sboms/upload
               │
               ▼
         parse_cyclonedx() / parse_spdx()
               │
               ▼
         store_sbom()  ──► DB (sboms + dependencies)
               │
               ▼
         scan_sbom.delay()  ──► RabbitMQ ──► Celery Worker
                                                │
                                                ▼
                                          scan_with_grype()
                                                │
                                                ▼
                                    DB (vulnerabilities +
                                    sbom_vulnerabilities)
                                                │
                                                ▼
                                    reconcile_vulnerabilities()
```

### Alert Flow

```
Celery Beat ──► check_alerts()  (periodic)
                    │
                    ▼
              Query: open vulns >= threshold for each enabled alert
                    │
                    ▼
              send_slack() / send_email()
```

## Data Model

14 tables, organized into these domains:

```
users ──► api_keys
users ──► login_tokens

projects ──► services ──► sboms ──► dependencies
                                    sboms ──► sbom_vulnerabilities ◄── vulnerabilities
projects ──► vulnerability_snapshots
projects ──► alert_configs ──► notifications
projects ──► pull_requests
```

### Key Tables

| Table | Purpose |
|-------|---------|
| `projects` | Top-level grouping |
| `services` | Microservices/containers within a project |
| `sboms` | Uploaded SBOMs with `raw_sbom` (JSONB) |
| `dependencies` | Parsed dependencies from each SBOM |
| `vulnerabilities` | CVE data with severity, CVSS, affected packages |
| `sbom_vulnerabilities` | M:N join with status (open/fixed) |
| `vulnerability_snapshots` | Daily per-project metrics |
| `alert_configs` | Alert rules with severity threshold |
| `notifications` | Sent notification history |
| `api_keys` | API keys for programmatic access |
| `login_tokens` | One-time codes for email login |
| `pull_requests` | Dependency update PR tracking |

## Directory Layout

```
app/api/          FastAPI routers (one module per resource)
app/services/     Business logic + Celery tasks
app/models/       SQLAlchemy ORM models
app/middleware/    Auth stack (cookie + API key)
app/templates/    Jinja2 templates + partials (HTMX)
app/static/       CSS, images
app/migrations/   Alembic migrations
app/tests/        pytest tests
```

## Configuration

All settings are defined in `app/config.py` using `pydantic-settings`, loaded from
`.env`. Settings include database connection, RabbitMQ broker, SMTP, Slack webhook,
and auth parameters.

## Async & Celery

- **All DB access is async** via `AsyncSession` and `asyncpg`
- **Blocking operations** (Grype scanning, vulnerability processing) run in Celery workers
- **Periodic tasks** (alert checking, snapshot creation, vulnerability rescan of the latest SBOMs) run via Celery Beat
- Workers use `NullPool` to avoid connection pinning across greenlets
