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

The Dockerfile at [`caddy/Dockerfile`](https://github.com/trottomv/argus-sbomguard/blob/main/caddy/Dockerfile) uses `xcaddy` to build Caddy 2.11.3 with the `corazawaf/coraza-caddy` module.

```dockerfile
RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy
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

## Configuration

Set these variables in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | `localhost` | Public domain for TLS |
| `LETSENCRYPT_EMAIL` | `admin@argus.local` | Email for Let's Encrypt |
| `PROXY_MEM_LIMIT` | `128M` | Container memory limit |
| `PROXY_CPU_LIMIT` | `0.5` | Container CPU limit |

## Logs

```bash
docker compose logs -f proxy
```

## Health

The proxy responds to `/healthz` with `200 OK` before applying WAF rules — useful for load balancer liveness checks. `/readyz` is proxied to the app so it reflects real readiness (DB + RabbitMQ).
