# Setup & Configuration

This page covers prerequisites, the `.env` configuration reference, and running
the stack **locally for development**.

> **Deploying to a server?** Follow the step-by-step [Deployment Guide](deployment.md)
> instead — it covers hardware requirements, DNS, Docker installation, and
> production configuration with copy-paste commands.

## Prerequisites

- [Docker](https://docs.docker.com/engine/install/) and Docker Compose v2
- Python 3.12+ (for local development only)

## Environment

Copy the example environment file and review the variables:

```bash
cp .env.example .env
```

### Generating strong secrets

For anything other than local development, replace the default `SECRET_KEY`
and the database/broker passwords:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(24))"   # POSTGRES_PASSWORD
python3 -c "import secrets; print(secrets.token_urlsafe(24))"   # RABBITMQ_PASSWORD
```

For a full picture of every secret, how to store them (`.env`, Docker secrets,
Kubernetes Secrets) and how to rotate them, see
[Secrets Management](operations/secrets-management.md).

### Variable reference

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPOSE_FILE` | `docker-compose.development.yml` | Compose entry point. Set to `docker-compose.remote.yml` for the remote stack |
| `BUILD_TARGET` | `development` | Docker build target (development / production) |
| `PULL_POLICY` | `always` | Image pull policy: `always` pulls on every `up`, `missing` pulls only if the image is absent locally |
| `POSTGRES_HOST` | `postgres` | Database hostname |
| `POSTGRES_PORT` | `5432` | Database port |
| `POSTGRES_USER` | `argus` | Database user |
| `POSTGRES_PASSWORD` | `argus` | Database password |
| `POSTGRES_DB` | `argus` | Database name |
| `RABBITMQ_HOST` | `rabbitmq` | Celery broker hostname |
| `RABBITMQ_PORT` | `5672` | Celery broker port |
| `RABBITMQ_USER` | `argus` | Broker user |
| `RABBITMQ_PASSWORD` | `argus` | Broker password |
| `RABBITMQ_VHOST` | (empty) | Broker vhost |
| `SECRET_KEY` | `change-me-to-a-random-secret` | **Change this.** Used for session signing. The app refuses to start if this is left at the default when `APP_ENV != development` |
| `APP_ENV` | `development` | `development` / `demo` / `production` (also used as the Docker image tag). Non-development requires a strong `SECRET_KEY` |
| `APP_VERSION` | `0.0.7-beta` | GHCR image tag used by the remote stack (`docker-compose.remote.yml`) |
| `LOG_LEVEL` | `info` | Application log level |
| `LOG_FORMAT` | `json` | Structured log output format: `json` (default, single-line JSON) or `text` |
| `GRPC_PORT` | `50051` | gRPC server port |
| `SMTP_HOST` | (empty) | SMTP server (Mailpit in dev: `mailpit`, port `1025`) |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | (empty) | SMTP user |
| `SMTP_PASSWORD` | (empty) | SMTP password |
| `SMTP_FROM` | `noreply@argus.local` | Sender address for outgoing mail |
| `SLACK_WEBHOOK_URL` | (empty) | Slack incoming webhook for alerts |
| `VULN_RESCAN_INTERVAL_SECONDS` | `43200` | Seconds between automatic vulnerability rescans of the latest SBOMs (12h default; 6h = `21600`, 24h = `86400`) |
| `ADMIN_EMAIL` | `admin@argus.local` | Admin user created on first start |
| `LOGIN_TOKEN_EXPIRE_MINUTES` | `15` | Email code validity |
| `SESSION_MAX_AGE_HOURS` | `1` | Session cookie lifetime |
| `SHOW_LOGIN_CODE_IN_RESPONSE` | `false` | Show the one-time login code directly on the login page (dev/demo). **Rejected when `APP_ENV=production`** |
| `DISPLAY_TIMEZONE` | `UTC` | Timezone for UI dates |
| `DOMAIN` | (empty) | Public domain for TLS (Caddy + Let's Encrypt) |
| `LETSENCRYPT_EMAIL` | `admin@argus.local` | Email for Let's Encrypt |
| `APP_MEM_LIMIT` | `512M` | App memory limit (remote stack) |
| `APP_CPU_LIMIT` | `1.0` | App CPU limit (remote stack) |
| `WORKER_MEM_LIMIT` | `512M` | Worker memory limit (remote stack) |
| `WORKER_CPU_LIMIT` | `1.0` | Worker CPU limit (remote stack) |
| `SCHEDULER_MEM_LIMIT` | `128M` | Scheduler memory limit (remote stack) |
| `SCHEDULER_CPU_LIMIT` | `0.5` | Scheduler CPU limit (remote stack) |
| `PROXY_MEM_LIMIT` | `128M` | Proxy memory limit (remote stack) |
| `PROXY_CPU_LIMIT` | `0.5` | Proxy CPU limit (remote stack) |
| `LOG_MAX_SIZE` | `10m` | Max size per container log file |
| `LOG_MAX_FILE` | `3` | Number of log files kept per container |

## Local Development

### Start the stack

```bash
# Build and start all services
docker compose up -d --build

# Watch app logs
docker compose logs -f app
```

Migrations run automatically on first startup via the container entrypoint;
for manual control you can also run:

```bash
docker compose exec app alembic upgrade head
```

### Services

| Service | Port | URL |
|---------|------|-----|
| App (FastAPI) | 8000 | [http://localhost:8000](http://localhost:8000) (API docs: [/api/docs](http://localhost:8000/api/docs)) |
| gRPC | 50051 | — |
| PostgreSQL | 5432 | — |
| RabbitMQ | 5672, 15672 | [http://localhost:15672](http://localhost:15672) |
| Mailpit | 1025, 8025 | [http://localhost:8025](http://localhost:8025) |
| Worker | — | Celery worker |
| Scheduler | — | Celery beat |

### Stop the stack

```bash
docker compose down          # stop and remove containers
docker compose down -v       # also delete volumes (postgres + rabbitmq data)
```

## First Login

1. Open [http://localhost:8000](http://localhost:8000)
2. Enter `admin@argus.local` (or your `ADMIN_EMAIL`)
3. Check [Mailpit](http://localhost:8025) for the one-time code (or your email
   inbox in production). With `SHOW_LOGIN_CODE_IN_RESPONSE=true` (dev/demo only)
   the code is also shown directly on the login page
4. Enter the code to sign in

## API Authentication

For programmatic access, generate an API key from **Settings** → **Generate Key**.
Pass it in the `X-API-Key` header:

```bash
curl -H "X-API-Key: argus_xxxxxxxxxxxx" http://localhost:8000/api/v1/projects
```

## What's Next

- [Deployment Guide](deployment.md) — deploy to your own server
- [Projects](guide/projects.md) — create projects and services
- [SBOMs](guide/sboms.md) — import CycloneDX / SPDX files
- [Reverse Proxy + WAF](guide/proxy.md) — Caddy and Coraza details
