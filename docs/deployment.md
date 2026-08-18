# Deployment Guide

This guide walks you through deploying Argus SBOM Guard on your own server,
step by step. Everything is copy-paste friendly: if you follow the steps in
order, you will end up with a running instance reachable over HTTPS.

The remote stack (`docker-compose.remote.yml`) includes:

- **FastAPI app + Celery worker + scheduler** — from the pre-built GHCR image
- **PostgreSQL 18** — persistent storage
- **RabbitMQ** — Celery broker
- **Caddy + Coraza WAF** — reverse proxy, automatic TLS via Let's Encrypt, and
  OWASP CRS v4.4.0 protection (see [Reverse Proxy + WAF](guide/proxy.md))

**Deployment type:** a container stack managed by [Docker Compose](https://docs.docker.com/compose/)
(v2). [Podman](https://podman.io/) (rootless) is a supported alternative — the
compose files run unmodified under `podman-compose`, see [Step 2](#step-2-install-the-container-runtime).

## Hardware Requirements

The resource limits below are the defaults already set in the compose files
(`APP_*_LIMIT`, `WORKER_*_LIMIT`, etc.). PostgreSQL and RabbitMQ run without
explicit limits, so the numbers already include realistic headroom for them and
for the CPU/RAM spikes Grype hits during vulnerability scans.

| | Minimum | Recommended |
|---|---|---|
| vCPU | 2 | 4 |
| RAM | 2 GB | 4 GB |
| Disk | 20 GB | 50 GB |
| OS | Ubuntu 22.04+ / Debian 12+ (64-bit) | same |

Disk space is dominated by the Docker images (~2–3 GB) plus the PostgreSQL
volume, which grows with every SBOM, dependency record, and vulnerability
snapshot you store. Start with 20 GB and monitor `docker system df`.

!!! note "Swap"
    If you use a 2 GB machine, a 2 GB swap file gives Grype and PostgreSQL
    comfortable headroom during large scans.

## Prerequisites

- A **VPS or dedicated server** (any provider works) with root access over SSH
- A **domain name** (e.g. `argus.example.com`) whose DNS you control
- Docker + Docker Compose v2 on the server (installed in [Step 2](#step-2-install-docker))

## Step 1 — Point DNS and open the firewall

1. Create an **`A` record** for your hostname pointing to your server's public
   IPv4 address:

   | Name | Type | Value |
   |------|------|-------|
   | `argus` | `A` | `<SERVER_IP>` |

   For `argus.example.com`, set the record name to `argus`. For a bare domain
   (`example.com`) set it to `@`.

2. Open inbound ports **22** (SSH), **80** and **443** (HTTP/HTTPS) on your
   server's firewall. On a typical Ubuntu server:

   ```bash
   sudo ufw allow 22/tcp
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

   Port 80 is only used to redirect to HTTPS and for the Let's Encrypt
   certificate issuance — after the first successful request it is not strictly
   required, but keep it open to allow certificate renewals.

## Step 2 — Install the container runtime

SSH into the server:

```bash
ssh root@<SERVER_IP>
```

Then install a container runtime. Argus SBOM Guard ships as a Docker Compose
stack; you can run it with either Docker or Podman.

=== "Docker (recommended)"

    Install Docker Engine + the Compose plugin with the official convenience
    script:

    ```bash
    curl -fsSL https://get.docker.com | sh
    ```

    Verify the installation:

    ```bash
    docker --version && docker compose version
    ```

    !!! note "Non-root user"
        If you SSH as a non-root user instead of `root`, add your user to the
        `docker` group so you can run `docker` without `sudo`:

        ```bash
        sudo usermod -aG docker $USER
        # log out and back in for the change to take effect
        ```

=== "Podman (rootless)"

    Install Podman plus `podman-compose` on Ubuntu/Debian:

    ```bash
    sudo apt-get update
    sudo apt-get install -y podman podman-compose
    ```

    Verify the installation:

    ```bash
    podman --version && podman-compose --version
    ```

    GHCR image pulls work out of the box. In every command in this guide,
    replace `docker compose` with `podman-compose`.

    !!! note "Feature parity"
        `pull_policy` and `deploy.resources.*` (the `*_MEM_LIMIT` / `*_CPU_LIMIT`
        variables in `.env`) are mostly ignored by `podman-compose` — treat those
        limits as guidance. Services, networks, volumes and healthchecks are all
        fully supported.

After the runtime is installed, the remaining steps of this guide use
`docker compose`. If you installed Podman, substitute `podman-compose`
throughout.

## Step 3 — Clone the repository

```bash
git clone https://github.com/trottomv/argus-sbomguard.git
cd argus-sbomguard
```

## Step 4 — Configure the environment

Create your environment file:

```bash
cp .env.example .env
```

Now generate strong secrets. Run this once and copy the output:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(24))"   # POSTGRES_PASSWORD
python3 -c "import secrets; print(secrets.token_urlsafe(24))"   # RABBITMQ_PASSWORD
```

Edit `.env` and set at minimum the following values:

| Variable | Example | Why it matters |
|----------|---------|----------------|
| `DOMAIN` | `argus.example.com` | Public hostname used for the `A` record; enables TLS via Let's Encrypt |
| `LETSENCRYPT_EMAIL` | `ops@example.com` | Email Let's Encrypt uses for expiry notifications |
| `APP_ENV` | `production` | Enables secure cookie + hardened behaviour; also sets the `DATABASE_URL`-independent app mode |
| `APP_VERSION` | `0.0.6-beta` | GHCR image tag to pull — use the [latest release](https://github.com/trottomv/argus-sbomguard/releases) |
| `SECRET_KEY` | (generated) | Signs the session cookie. **Required** — the app refuses to start when `APP_ENV != development` |
| `ADMIN_EMAIL` | `admin@example.com` | Admin account created on first start |
| `POSTGRES_PASSWORD` | (generated) | Database password — **change the default** |
| `RABBITMQ_PASSWORD` | (generated) | Broker password — **change the default** |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` | your provider | Needed for email login codes and notifications. Without SMTP, users cannot sign in |

!!! danger "Never use the defaults in production"
    Leaving `SECRET_KEY`, `POSTGRES_PASSWORD` or `RABBITMQ_PASSWORD` at their
    example values means the app refuses to start (SECRET_KEY) or exposes your
    database and broker with well-known credentials.

!!! warning "APP_ENV=production"
    With `APP_ENV=production`, `SHOW_LOGIN_CODE_IN_RESPONSE` is rejected by the
    app — login codes are only delivered by email. This is intentional.

Then point the compose stack at the remote file. The simplest way is to set the
variable in `.env`:

```bash
sed -i 's|^COMPOSE_FILE=.*|COMPOSE_FILE=docker-compose.remote.yml|' .env
```

## Step 5 — Start the stack

```bash
docker compose up -d
```

This pulls the images and starts, in order: PostgreSQL → RabbitMQ → app,
worker, scheduler → Caddy proxy. Migrations run automatically on first startup
(via the container entrypoint) — no manual `alembic` step is required.

Watch startup:

```bash
docker compose logs -f app
```

## Step 6 — Verify

Check that all services are healthy:

```bash
docker compose ps
```

The `/healthz` endpoint answers `200 OK` from Caddy *before* the WAF rules are
applied; `/readyz` is proxied to the app so it reflects real readiness:

```bash
curl -sS -o /dev/null -w "%{http_code}\n" https://argus.example.com/healthz
```

Expected: `200`. If you get a TLS warning instead, DNS has not propagated yet
(see [Troubleshooting](#troubleshooting)).

## Step 7 — First login

1. Open `https://argus.example.com` in your browser.
2. Enter `ADMIN_EMAIL` from your `.env`.
3. Check the inbox for the one-time code and enter it.

!!! tip "Show the login code without email"
    To avoid waiting for the email while testing, temporarily set
    `APP_ENV=demo` and `SHOW_LOGIN_CODE_IN_RESPONSE=true`; the one-time code is
    then shown directly on the login page regardless of SMTP — but **never** run
    `APP_ENV=production` with the code shown in the response.

## Maintenance

### Updating to a new release

```bash
cd argus-sbomguard
git pull
# Set APP_VERSION to the new tag in .env (or leave it as the latest release)
docker compose pull
docker compose up -d
```

### Logs

```bash
docker compose logs -f app      # FastAPI app
docker compose logs -f worker   # Celery worker (Grype scans)
docker compose logs -f proxy    # Caddy + WAF
```

### Backups

The only state you must back up is the PostgreSQL volume. The bundled script
dumps the database (`pg_dump`), compresses it with gzip, and prunes old backups
(default: keep the 7 most recent). It can run while the stack is up:

```bash
./scripts/backup.sh
```

Everything DB-related (`pg_dump`, `psql`, `gzip`) runs inside the `postgres`
container, and encryption inside the `app` container — the host only needs
`docker` and a standard shell.

Backups are written to `backups/` (gitignored) as `argus_<timestamp>.sql.gz`
(or `.sql.gz.enc` when encryption is enabled). The script honours `COMPOSE_FILE`,
`BACKUP_DIR`, `BACKUP_RETENTION` and `BACKUP_ENCRYPTION_KEY` from `.env`.
Override the retention or output directory with environment variables:

```bash
BACKUP_RETENTION=30 ./scripts/backup.sh
BACKUP_DIR=/var/backups/argus ./scripts/backup.sh
```

Set `BACKUP_RETENTION=0` to keep every backup.

#### Encrypted backups (optional)

Backups contain sensitive data (user emails, SBOMs, projects), so enable
encryption with a dedicated key, independent from `SECRET_KEY`:

```bash
echo "BACKUP_ENCRYPTION_KEY=$(openssl rand -base64 32)" >> .env
docker compose up -d   # recreate the app container so the key reaches it
```

Backups are then written encrypted (`argus_*.sql.gz.enc`) using the `app`
container's `openssl` (AES-256-CBC + PBKDF2, 600,000 iterations). Restore works
the same way — the key must still be set in `.env`.

!!! warning "Not authenticated"
    `openssl enc` supports no AEAD ciphers (no bcrypt/GCM), so encrypted backups
    are checked for integrity by decrypting and running `gzip -t`, which catches
    accidental corruption but not deliberate tampering. For authenticated
    encryption use a dedicated tool such as `age`.

!!! tip "RabbitMQ data"
    RabbitMQ stores queued tasks only; a clean restart simply starts from an
    empty queue. No backup needed.

### Restoring

To restore a backup, pass the file to the restore script. `--reset` drops and
recreates the database first — required when restoring into an existing
deployment, since the dump does not overwrite existing tables:

```bash
docker compose stop app worker scheduler   # free database connections
./scripts/restore.sh backups/argus_20260818_123456.sql.gz --reset
docker compose start app worker scheduler
```

The script accepts `.sql`, `.sql.gz` and encrypted `.sql.gz.enc` files. Stop the
app stack first, or the restore fails with `database is being accessed by other
users`. Encrypted backups require `BACKUP_ENCRYPTION_KEY` set in `.env`;
decryption runs in a throwaway app container (`docker compose run`), so it works
even with the stack stopped.

!!! danger "Destructive"
    `--reset` destroys the current database contents before restoring. Only use
    it when you intend to replace the live data (or on a staging copy).

### Restore drill

Practice restoring regularly so an incident never involves a first-time restore.
The drill below restores a backup into the live stack — this intentionally
destroys current data, so run it on a staging copy or accept the data loss.

1. Create a backup:

   ```bash
   ./scripts/backup.sh
   ```

2. Stop the app so nothing holds database connections:

   ```bash
   docker compose stop app worker scheduler
   ```

3. Restore the most recent backup (drops and recreates the database):

   ```bash
   latest=$(ls -t backups/argus_*.sql.gz* | head -1)
   ./scripts/restore.sh "$latest" --reset
   ```

4. Start the stack:

   ```bash
   docker compose start app worker scheduler
   ```

5. Verify the data survived — sign in and open a project, or query directly:

   ```bash
   docker compose exec -T postgres psql -U argus argus -c "select count(*) from projects;"
   ```

   The count should match the backup you restored. Finish the drill by running
   another `./scripts/backup.sh` so the restored state is captured by the
   retention-pruned set.

## Publishing behind an existing reverse proxy

If you already run nginx, Traefik or another proxy, you can skip the built-in
Caddy/WAF proxy and publish the app directly. To do that:

1. Do **not** set `DOMAIN` (or leave it empty) so Caddy only binds internally
   and does not try to obtain certificates.
2. Expose port 8000 on your host by adding it to the `app` service, or use the
   Docker network so your proxy can reach the container by name.
3. Let your external proxy terminate TLS and forward requests to `app:8000`.

The trade-off: you lose the Coraza WAF and automatic Let's Encrypt handling
provided by the bundled proxy. For most deployments the built-in Caddy stack is
the simpler and safer option.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `curl` to the domain fails with a certificate error | DNS not propagated / certificate not yet issued | Wait a few minutes, verify the `A` record resolves (`dig +short argus.example.com`), then restart Caddy: `docker compose restart proxy` |
| App logs show `secret_key must be set...` | `SECRET_KEY` left at default | Generate a strong value (Step 4) and restart: `docker compose up -d` |
| Login code never arrives | Email not delivered | Check the SMTP `SMTP_*` settings and Mailpit, or use `APP_ENV=demo` + `SHOW_LOGIN_CODE_IN_RESPONSE=true` to show the code on the login page |
| Requests are blocked with `403` | WAF rule fired | Check `docker compose logs proxy`; review the allowed methods/URI patterns in [`caddy/Caddyfile`](https://github.com/trottomv/argus-sbomguard/blob/main/caddy/Caddyfile) |
| App keeps restarting with a DB error | Migrations failed to apply | Check `docker compose logs app` — migrations retry up to 10 times before the app continues |
