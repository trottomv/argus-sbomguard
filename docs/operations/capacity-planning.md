# Capacity Planning

This page helps you size an Argus SBOM Guard deployment that will actually last,
and tells you what to watch so you can right-size before a bottleneck bites.
The [Deployment Guide](../deployment.md#hardware-requirements) gives the minimum
and recommended starting points (2 vCPU / 2 GB RAM minimum, 4 vCPU / 4 GB
recommended). This page explains **why** those numbers exist and how they scale
with your workload.

## What consumes resources

| Resource | Main consumers | Notes |
|----------|----------------|-------|
| **Disk** | PostgreSQL volume, backup directory, Docker images + container logs | PostgreSQL grows with every SBOM, dependency, vulnerability link and daily snapshot |
| **RAM** | PostgreSQL, worker (Grype), app | Grype spawns per-SBOM scan processes that spike memory during scans |
| **CPU** | Worker (Grype), app, PostgreSQL | Grype is CPU-bound; the worker runs `--concurrency=4` by default |
| **Network** | Grype DB updates, Slack webhook, SMTP | Outbound only, modest. Grype downloads/refreshes its local vulnerability DB on first use; no per-scan external API calls |

RabbitMQ is **transient**: it only holds queued tasks and needs no backup or
persistent capacity planning
([deployment.md](../deployment.md#backups)). The same is true of the Caddy/WAF
proxy and the OTel Collector.

## Sizing by workload

Argus stores the raw SBOM JSON and derives rows from it, so disk growth is a
function of how many SBOMs you upload and how big they are:

| Input | What is stored |
|-------|----------------|
| Raw SBOM | `sboms.raw_sbom` (the full CycloneDX/SPDX JSON) |
| Per package in the SBOM | one row in `dependencies` (+ `metadata` JSONB) |
| Per matched vulnerability | a `vulnerabilities` row + a `sbom_vulnerabilities` link |
| Daily (hourly) | `vulnerability_snapshots` rows per project |

A rough mental model: **a 10 MB SBOM with ~5,000 dependencies will typically
grow the database by 50–100 MB** once parsed, indexed and scanned — the raw JSON
is the biggest single item, and Grype finds vulnerabilities for a small
percentage of the dependencies. SBOMs of application builds (a few thousand
dependencies) are the common case and stay in the low tens of MB each. Measure
your own reality with:

```sql
docker compose exec -T postgres psql -U argus argus -c "
  select
    pg_size_pretty(pg_database_size('argus'))            as db_size,
    (select count(*) from sboms)                          as sboms,
    (select count(*) from dependencies)                   as dependencies,
    (select count(*) from sbom_vulnerabilities)           as vuln_links,
    (select count(*) from vulnerability_snapshots)        as snapshots;
"
```

Then project growth: multiply your upload rate (SBOMs per week) by the measured
per-SBOM footprint, add the daily snapshot growth, and leave headroom for a
major scan spike.

### Storage breakdown

| Store | Default | Tune with | Notes |
|-------|---------|-----------|-------|
| PostgreSQL volume | `postgres_data` | — | The only state that matters for DR |
| Backup directory | `backups/` (`./backups`) | `BACKUP_DIR`, `BACKUP_RETENTION` | gzipped dumps; encrypted (`*.sql.gz.enc`) when `BACKUP_ENCRYPTION_KEY` is set |
| Container logs | local driver | `LOG_MAX_SIZE`, `LOG_MAX_FILE` | Defaults: 10 MB × 3 files per container |
| Docker images | — | prune with `docker image prune` | ~2–3 GB on disk; one per `APP_VERSION` |
| RabbitMQ volume | `rabbitmq_data` | — | Transient; bounded by queue depth, not growth |

## Worker and Grype spikes

The worker runs Celery with `--concurrency=4`
([docker-compose/app.yml](https://github.com/trottomv/argus-sbomguard/blob/main/docker-compose/app.yml))
and a default memory limit of `WORKER_MEM_LIMIT=512M`. Every SBOM upload
triggers a Grype scan, and Grype loads the SBOM into memory and may spawn
sub-processes. A **large** SBOM (huge monorepo, OS image with tens of thousands
of packages) during a scan burst can push the worker near its 512 MB limit —
the pod then gets OOM-killed and the task retries.

Signs you are hitting this:

```bash
docker compose logs worker | grep -i "memory\|killed\|retry"
```

If the worker is OOM-killed during scans:

- Raise `WORKER_MEM_LIMIT` (e.g. `1024M`) and `WORKER_CPU_LIMIT` in `.env`,
  then `docker compose up -d`.
- Or lower Celery concurrency by overriding the worker command
  (`--concurrency=2`). Fewer concurrent scans = less memory, slower throughput.
- Or raise `VULN_RESCAN_INTERVAL_SECONDS` (default 12 h). Every rescan run
  re-scans **all** latest SBOMs in one batch, so a shorter interval means more
  frequent full batches and more Grype load, not less.

There is no horizontal scaling knob yet — the stack ships a single worker. If
scans back up, check the queue depth:

```bash
docker compose exec rabbitmq rabbitmqctl list_queues
```

## Backup storage

Every backup is a full `pg_dump` + gzip of the database, so the backup
directory grows by roughly the gzipped database size per backup. With the
default `BACKUP_RETENTION=7` you keep 7 such files:

```bash
# rough estimate of your backup footprint at steady state
du -sh backups/
```

For a 1 GB database that is ~1–2 GB of backups (dumps compress well). Budget
`BACKUP_RETENTION × backup size` for the backup volume, and remember to also
account for the **off-box copy** you keep for disaster recovery — see
[Disaster Recovery](disaster-recovery.md).

## CPU and RAM across services

| Service | Default limit (remote) | What drives it | When to raise |
|---------|------------------------|----------------|---------------|
| `app` | `APP_MEM_LIMIT=512M`, `APP_CPU_LIMIT=1.0` | Web requests, rendering, JSONB parsing | Concurrent API traffic; large SBOM uploads |
| `worker` | `WORKER_MEM_LIMIT=512M`, `WORKER_CPU_LIMIT=1.0` | Grype scans | Large SBOMs, scan bursts (see above) |
| `scheduler` | `SCHEDULER_MEM_LIMIT=128M`, `SCHEDULER_CPU_LIMIT=0.5` | Celery beat only | Almost never |
| `proxy` | `PROXY_MEM_LIMIT=128M`, `PROXY_CPU_LIMIT=0.5` | Caddy + Coraza WAF | High request volume; WAF rule cost |
| PostgreSQL | no explicit limit | Queries, indexes, `VACUUM` | Largest resident footprint on the box |
| RabbitMQ | no explicit limit | Queue depth, connections | Sustained scan backlogs |

## Tuning knobs summary

| Setting | Default | Effect on capacity |
|---------|---------|--------------------|
| `BACKUP_RETENTION` | `7` | Backups kept; set `0` to keep all (grows disk) |
| `BACKUP_DIR` | `./backups` | Where backups land; put it outside the repo on a separate disk in production |
| `VULN_RESCAN_INTERVAL_SECONDS` | `43200` (12 h) | How often the latest SBOM is rescanned; lower = more Grype load |
| `LOG_MAX_SIZE` / `LOG_MAX_FILE` | `10m` / `3` | Bounds per-container log disk use |
| `LOGIN_RATE_LIMIT` / `API_RATE_LIMIT` | `10` / `120` | Bounds proxy request load; see [Reverse Proxy + WAF](../guide/proxy.md#configuration) |

## Monitoring and right-sizing

The stack already exposes host metrics at `/metrics` through the OTel Collector
(CPU, memory, disk, load, network) — see [Observability](../guide/observability.md).
Wire a Prometheus scraper to those and alert on:

- **Disk utilization** (`filesystem_utilization`) on the PostgreSQL volume and
  the backup directory — the most common silent failure is running out of disk.
- **Worker memory** near the 512 MB limit.
- **RabbitMQ queue depth** (broker metric, if exported) growing over time.

On the box itself:

```bash
docker system df          # images + volumes + build cache usage
df -h                     # host disk, including BACKUP_DIR volume
```

The two rules of thumb: **disk is what runs out first**, and **Grype is what
makes the worker spike**. Size for those two and everything else follows.

## Worked example

A team uploads 50 SBOMs/week averaging 5 MB each with ~2,500 dependencies.
Measured footprint per SBOM is ~30 MB in PostgreSQL. They scan every SBOM once
on upload, keep 7 backups, and store them off-box:

- **DB growth**: 50 × 30 MB ≈ 1.5 GB/week ≈ 78 GB/year before pruning anything
  (SBOMs older than `SBOM_RETENTION_DAYS` are auto-pruned; backups and snapshots
  are pruned too).
- **Backup growth**: DB 1.5 GB after week 1 → backup ~0.7 GB gzipped → 7 × 0.7
  GB ≈ 5 GB at steady state (plus the off-box copy).
- **Sizing**: 100 GB disk comfortably covers a year of DB + backups + images;
  monitor monthly and adjust. If SBOMs balloon (one 2 GB image SBOM/week),
  re-measure — the per-SBOM model is linear.

!!! note "Auto-pruning"
    Backups are pruned by `BACKUP_RETENTION`, daily vulnerability snapshots by
    `SNAPSHOT_RETENTION_DAYS` (default 30, range 30–180, always on) and old
    SBOMs by `SBOM_RETENTION_DAYS` (default 365; set to `0` to keep SBOMs
    forever — an empty value also works when injected as a container env var —
    and keeps the latest SBOM per service/project as a safety net).
    Dependencies are removed together with their SBOM. Plan disk for sustained
    growth, or delete old SBOMs/projects through the UI to reclaim space.
