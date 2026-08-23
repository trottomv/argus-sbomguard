# Disaster Recovery

Disaster recovery (DR) answers one question: **when the server dies, how long
until the platform is back and how much data can we afford to lose?** For Argus
the answer is simple, because only one piece of state matters:

> **The only state you must protect is the PostgreSQL database.** Everything
> else — the app, worker, scheduler, Caddy/WAF, OTel Collector, RabbitMQ — is
> rebuilt from images and configuration.

Backups and the restore mechanics are covered in the
[Deployment Guide](../deployment.md#backups) and the
[Upgrade & Rollback Runbook](../development/upgrades.md). This page turns them
into a DR plan with concrete RPO/RTO targets, per-scenario runbooks, and the
drill you should run before you ever need them.

## Defining your targets

| Term | Meaning | Your lever |
|------|---------|-----------|
| **RPO** (Recovery Point Objective) | How much data you accept losing | Backup **frequency**. Every backup is a full dump, so RPO ≈ the interval between backups |
| **RTO** (Recovery Time Objective) | How long until the platform is back | Restore speed + re-provisioning + verification time |

The defaults in the stack target a **daily-backup, hours-to-recover** profile:
`BACKUP_RETENTION=7` with a manual or cron-driven `just db-backup`. If you need
a tighter RPO, back up more often (a full dump every few hours is fine at this
scale) and script the off-box copy.

!!! tip "Lower RPO if you need it"
    For near-zero RPO you would need PostgreSQL streaming/WAL archiving, which
    the stack does **not** ship by default. A more frequent full-dump schedule
    (e.g. hourly via cron) is the supported, low-effort way to shrink RPO.

## What survives and what does not

| Asset | Survives a server loss? | How to protect it |
|-------|------------------------|-------------------|
| PostgreSQL data | Only via a backup | `just db-backup`, kept off-box |
| `app`/`worker`/`scheduler` images | Yes | Pulled from GHCR (`APP_VERSION` tag) |
| `backup` image | Yes | Built/pushed once; see [Backups on Kubernetes](../deployment.md#backups-on-kubernetes) |
| `.env` configuration | **No** | Back it up or re-derive it (see below) |
| RabbitMQ queued tasks | No | Irrelevant — a restart starts from an empty queue |
| Caddy certs | Re-issued | Let's Encrypt re-issues automatically after DNS is back |

**`.env` is state.** Losing the server also loses your secrets and settings.
Keep a copy of `.env` (or the values) somewhere safe but not in git — a
password manager, a sealed vault, or an encrypted backup. Recovery without it
means regenerating every secret and reconfiguring SMTP, Slack, and rate limits.
See [Secrets Management](secrets-management.md).

## Recovery scenarios

### Scenario 1 — Database corrupted or a bad migration (same host)

Use the restore path, which drops and recreates the database. Full procedure in
the [Upgrade & Rollback Runbook](../development/upgrades.md) — the short form:

```bash
docker compose stop app worker scheduler        # free DB connections
just db-restore argus_<timestamp>.sql.gz --reset
docker compose start app worker scheduler
```

Verify (counts should match the backup):

```bash
docker compose exec -T postgres psql -U argus argus \
  -c "select count(*) from projects;"
```

### Scenario 2 — Full server loss (new host)

The goal is a **from-scratch re-provision** using only: the GHCR images, a
`.env` copy, and the latest off-box backup.

1. **Provision a new server** and install Docker Compose (or Podman) — follow
   [Deployment Guide Steps 1–3](../deployment.md#step-1-point-dns-and-open-the-firewall).
2. **Recreate `.env`** from your saved copy (or re-generate per the guide) and
   set `COMPOSE_FILE=docker-compose.remote.yml`. Do not change `SECRET_KEY`
   unless you accept invalidating every active session.
3. **Restore the database before starting the app** — the app runs migrations
   on boot, so restore first, then start:

   ```bash
   # fetch the backup from your off-box storage (see below)
   cp /path/to/off-box/argus_20260818_123456.sql.gz backups/

   # start only postgres + rabbitmq + backup (not app yet)
   docker compose up -d postgres rabbitmq backup

   # wait for postgres to be healthy, then restore
   just db-restore argus_20260818_123456.sql.gz --reset
   ```

4. **Start the rest of the stack** and verify:

   ```bash
   docker compose up -d
   docker compose ps                          # all healthy
   curl -sS -o /dev/null -w "%{http_code}\n" https://argus.example.com/readyz   # 200
   ```

5. **Point DNS at the new host** (lower the TTL beforehand if you planned for
   this) and confirm TLS is re-issued by Caddy.
6. **Take a fresh backup** so the new host's baseline is captured.

!!! danger "Order matters"
    Restore **before** the first `docker compose up -d`, because the app
    entrypoint runs `alembic upgrade head` on boot. If the app boots against an
    empty database it will create a new (empty) schema and the later restore
    still works (it drops and recreates), but you avoid confusing states by
    restoring first.

### Scenario 3 — Ransomware or accidental deletion

Same as Scenario 1, but the trigger is logical damage rather than hardware.
Restore the newest backup that predates the damage. This is exactly why the
**off-box copy** exists — an attacker or a bad script that can reach the server
can also reach backups stored only on it.

## The off-box copy

A backup that lives only on the server is not a backup for DR purposes. After
each `just db-backup`, copy `BACKUP_DIR` elsewhere. Any tool works; two common
patterns:

=== "rsync to a second host"

    ```bash
    rsync -av backups/ backup@other-host:/srv/backups/argus/
    ```

=== "Object storage (S3-compatible)"

    ```bash
    aws s3 sync backups/ s3://my-bucket/argus/backups/ --sse
    ```

The [Upgrade & Rollback Runbook](../development/upgrades.md) already makes the
off-box copy a mandatory pre-upgrade step — make it a scheduled job too, so it
is never dependent on a human remembering it.

## The DR drill

Do not discover restore on the day of the incident. Run this drill on a
**scratch host** (or a staging copy of the stack) on a schedule — monthly is a
sane cadence. The existing [restore drill](../deployment.md#restore-drill)
validates the same-host restore; this one validates the full **new-host**
path:

1. **Create and off-box a backup**: `just db-backup`, then sync `backups/`
   off-box (the exact artifact you would recover from).
2. **Provision a fresh host** and reproduce Scenario 2: clone the repo, restore
   `.env`, restore the database from the off-box copy.
3. **Verify data**: `select count(*)` on `projects`, `sboms` and
   `sbom_vulnerabilities` must match the backup. Sign in, open a project, view
   an SBOM and the Vulnerabilities page.
4. **Verify a scan still works**: upload a small SBOM and confirm the worker
   scans it without errors (`docker compose logs worker`).
5. **Record** the elapsed time (your measured RTO) and any friction in your
   incident runbook.

!!! note "Fresh host is the honest test"
    Restoring onto the *same* host hides two common failure modes: you cannot
    re-provision a host, or your backup tooling depends on something the new
    host does not have (a locally built `backup` image, host paths, etc.).
    Every few drills, build the `backup` image from scratch on the new host to
    prove the image pipeline, not just the dump.

## Incident checklist (print this)

1. [ ] Identify scope: DB only, or full host loss?
2. [ ] Stop app/worker/scheduler if restoring into a live stack.
3. [ ] Pick the newest backup that predates the damage / is intact.
4. [ ] Verify the backup integrity (`gzip -t` on the file) before starting.
5. [ ] Restore (Scenario 1 or 2 above).
6. [ ] Start the stack and verify `/readyz` + row counts.
7. [ ] Sign in and smoke-test: project, SBOM, vulnerabilities, a fresh scan.
8. [ ] Take a fresh backup immediately so the recovered state is the baseline.
9. [ ] Log what happened and which backup was restored (per the runbook).
