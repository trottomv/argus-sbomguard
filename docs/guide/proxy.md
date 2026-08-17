# Reverse Proxy (Caddy + Coraza WAF)

The `proxy` service sits in front of the FastAPI application, terminating TLS, routing gRPC traffic, and applying the OWASP Core Rule Set (CRS) v4.4.0 via the Coraza WAF module.

## Architecture

```
Client ──:443──→ proxy ──:8000──→ app (FastAPI)
                 proxy ──:50051──→ app (gRPC h2c)
```

- **TLS termination** at the proxy (Let's Encrypt via `LETSENCRYPT_EMAIL`)
- **gRPC passthrough** via `h2c://app:50051`
- **HTTP reverse proxy** to `app:8000` with WAF inspection

## Build

The Dockerfile at [`caddy/Dockerfile`](https://github.com/trottomv/argus-sbomguard/blob/main/caddy/Dockerfile) uses `xcaddy` to build Caddy 2.11.3 with the `corazawaf/coraza-caddy` and `mholt/caddy-ratelimit` modules.

```dockerfile
RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy \
    --with github.com/mholt/caddy-ratelimit
```

The OWASP CRS v4.4.0 archive is downloaded and extracted to `/etc/caddy/crs/` at build time.

## WAF Rules

The [`caddy/Caddyfile`](https://github.com/trottomv/argus-sbomguard/blob/main/caddy/Caddyfile) includes 27 OWASP CRS rule files covering:

- Protocol enforcement
- Scanner detection
- LFI / RFI / RCE
- XSS and SQL injection
- PHP/Java generic attacks
- Session fixation
- Data leakages
- Web shells

Plus 4 custom rules:

| Rule | ID | Description |
|------|----|-------------|
| SSTI | `1001` | Blocks template injection patterns (`{{.*}}`) |
| SQLi | `1002` | Blocks SQL injection heuristics |
| XSS | `1003` | Blocks `<script>` tags |
| Path traversal | `1004` | Blocks `../` and `./` patterns |

All rules run in blocking mode (`SecRuleEngine On`) with request body inspection enabled.

## Rate Limiting

The proxy applies rate limiting via the `caddy-ratelimit` module, before the WAF and reverse proxy. Two zones are defined, both keyed per client IP (grouped by IPv6 `/64` prefix) over a 1-minute sliding window:

| Zone | Scope | Description |
|------|-------|-------------|
| `login` | `POST /login`, `POST /login/verify` | Caps login attempts per client IP |
| `api` | `/api/v1/*` | Caps API requests per client IP |

The keys are based on the client IP only — the `X-API-Key` header is deliberately *not* part of the key, so a client cannot bypass its per-source budget by cycling arbitrary header values. When a limit is hit, Caddy returns `429 Too Many Requests` with a `Retry-After` header.

`/healthz` responds before rate limiting, so health checks are never throttled.

## Configuration

Set these variables in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | `localhost` | Public domain for TLS |
| `LETSENCRYPT_EMAIL` | `admin@argus.local` | Email for Let's Encrypt |
| `LOGIN_RATE_LIMIT` | `10` | Max `POST /login` / `POST /login/verify` per client IP per minute |
| `API_RATE_LIMIT` | `120` | Max `/api/v1/*` requests per client IP per minute |
| `PROXY_MEM_LIMIT` | `128M` | Container memory limit |
| `PROXY_CPU_LIMIT` | `0.5` | Container CPU limit |

Rate-limit storage is in-memory per proxy instance; distributed limiting via Redis is planned but not yet enabled.

## Logs

```bash
docker compose logs -f proxy
```

## Health

The proxy responds to `/healthz` with `200 OK` before applying WAF rules — useful for load balancer liveness checks. `/readyz` is proxied to the app so it reflects real readiness (DB + RabbitMQ).

`/metrics` is routed directly to the OTel Collector (bypassing rate limiting and the WAF) so Prometheus can scrape it without being throttled or blocked. See [Observability](observability.md).

!!! warning "Security: `/metrics` is unauthenticated"

    `/metrics` exposes **host metrics** (CPU, memory, disk, network, host name)
    scraped by the Collector from the host filesystem, and is intentionally left
    unauthenticated so a Prometheus scraper can poll it without credentials.
    If the `DOMAIN` is publicly reachable, anyone can read infrastructure
    details from `https://<DOMAIN>/metrics`. For public deployments:

    - restrict scraping to a private network / VPN where possible, or
    - put the Collector behind a firewall rule that only allows your Prometheus
      instance, or
    - accept the exposure (the metrics contain no application secrets).

    There is currently no token/`basic_auth` option for `/metrics`; it is an
    all-or-nothing public path.
