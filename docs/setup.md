# Setup & Configuration

## Prerequisites

- [Docker](https://docs.docker.com/engine/install/) and Docker Compose v2
- Python 3.12+ (for local development only)

## Environment

Copy the example environment file and review the variables:

```bash
cp .env.example .env
```

Key settings in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | — | **Change this.** Used for session signing |
| `APP_ENV` | `development` | `development` / `demo` / `production` (also used as the Docker image tag). Non-development requires a strong `SECRET_KEY` |
| `ADMIN_EMAIL` | `admin@argus.local` | Admin user created on first start |
| `PULL_POLICY` | `always` | Image pull policy for compose services: `always` pulls on every `up`, `missing` pulls only if the image is absent locally |
| `POSTGRES_HOST` | `postgres` | Database hostname |
| `POSTGRES_PASSWORD` | `argus` | Database password |
| `RABBITMQ_HOST` | `rabbitmq` | Celery broker hostname |
| `SMTP_HOST` | — | SMTP server (Mailpit in dev) |
| `SLACK_WEBHOOK_URL` | — | Slack incoming webhook |
| `VULN_RESCAN_INTERVAL_SECONDS` | `43200` | Seconds between automatic vulnerability rescans of the latest SBOMs (12h default; 6h = `21600`, 24h = `86400`) |
| `DISPLAY_TIMEZONE` | `UTC` | Timezone for UI dates |
| `SESSION_MAX_AGE_HOURS` | `1` | Session cookie lifetime |
| `LOGIN_TOKEN_EXPIRE_MINUTES` | `15` | Email code validity |
| `SHOW_LOGIN_CODE_IN_RESPONSE` | `false` | Show the one-time login code directly on the login page (dev/demo without SMTP). **Rejected when `APP_ENV=production`** |

## Starting the Application

### Development

```bash
# Build and start all services
docker compose up -d

# Run database migrations
docker compose exec app alembic upgrade head

# Watch logs
docker compose logs -f app
```

The development stack includes:

| Service | Port | URL |
|---------|------|-----|
| App (FastAPI) | 8000 | [http://localhost:8000](http://localhost:8000) (Swagger: [/api/docs](http://localhost:8000/api/docs)) |
| gRPC | 50051 | — |
| PostgreSQL | 5432 | — |
| RabbitMQ | 5672, 15672 | [http://localhost:15672](http://localhost:15672) |
| Mailpit | 1025, 8025 | [http://localhost:8025](http://localhost:8025) |
| Worker | — | Celery worker |
| Scheduler | — | Celery beat |

### Production

For production deployment, use the remote compose file:

```bash
cp .env.example .env
# Edit .env — set DOMAIN, LETSENCRYPT_EMAIL, SMTP_*, SLACK_WEBHOOK_URL, a strong SECRET_KEY
COMPOSE_FILE=docker-compose.remote.yml docker compose up -d
```

The remote stack includes Caddy as a reverse proxy with Coraza WAF.

## First Login

1. Open [http://localhost:8000](http://localhost:8000)
2. Enter `admin@argus.local` (or your `ADMIN_EMAIL`)
3. Check [Mailpit](http://localhost:8025) for the one-time code (or your email inbox in production). With `SHOW_LOGIN_CODE_IN_RESPONSE=true` (dev/demo only) the code is also shown directly on the login page
4. Enter the code to sign in

## API Authentication

For programmatic access, generate an API key from **Settings** → **Generate Key**.
Pass it in the `X-API-Key` header:

```bash
curl -H "X-API-Key: argus_xxxxxxxxxxxx" http://localhost:8000/api/v1/projects
```
