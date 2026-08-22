# Upgrade & Rollback Runbook

This runbook covers upgrading an Argus SBOM Guard deployment to a new release
and rolling it back if something goes wrong. Follow it in order: the pre-upgrade
dump is not optional.

## How upgrades work

- Releases are published as SemVer tags (`v0.0.7-beta`, …). The image tag to run
  is pinned by `APP_VERSION` in `.env` (default `0.0.7-beta`).
- **Migrations run automatically**: the `app` container entrypoint runs
  `alembic upgrade head` before starting uvicorn, retrying up to 10 times.
  Only the `app` container runs migrations — `worker` and `scheduler` start
  Celery directly and never touch the schema.
- Migrations are sequential files (`NNNN_description.py`) in
  `app/migrations/versions/`, each chained to the previous one via
  `down_revision`. The current head is whatever the newest revision is (find it
  with `alembic history`).
- An upgrade therefore never requires a manual `alembic` invocation: setting a
  new `APP_VERSION` and recreating the `app` container is enough.

!!! note "Pre-stable migration chain"
    The migration chain is not frozen until the first stable release — at that
    point the pre-stable migrations may be squashed into a single baseline.
    Never hardcode revision numbers in scripts or runbooks; always resolve them
    from the release notes or `alembic history`.

## Backup strategy

The only state that needs backing up is the PostgreSQL volume. RabbitMQ only
stores queued tasks — a clean restart starts from an empty queue, so it needs no
backup.

| Aspect | Setting | Notes |
|--------|---------|-------|
| Mechanism | `pg_dump` + gzip | `scripts/backup.sh` / `scripts/restore.sh`, ecosystem-agnostic |
| Schedule | Your cron / `CronJob` | The compose stack ships a `backup` service; see [Backups on Kubernetes](../deployment.md#backups-on-kubernetes) |
| Retention | `BACKUP_RETENTION` (default 7) | `0` keeps every backup |
| Encryption | `BACKUP_ENCRYPTION_KEY` | AES-256-CBC + PBKDF2 via `openssl`, independent of `SECRET_KEY` |
| Location | `BACKUP_DIR` (default `backups/`) | Point it outside the repo in production |

`just db-backup` creates a backup while the stack is up; the script verifies the
archive (`gzip -t`, or decrypt + `gzip -t` for encrypted backups) before
finishing.

!!! tip "Practice restoring"
    Run the [restore drill](../deployment.md#restore-drill) on a staging copy
    regularly so an incident never involves a first-time restore.

## Before you upgrade

1. **Read the release notes** for the target version and note any
   **destructive or irreversible migrations** (the
   [appendix](#appendix-assessing-migration-reversibility) explains how to
   assess a migration).
2. **Check the current stack is healthy**: `docker compose ps` shows all
   services `healthy`/`running` and `/readyz` answers `200`.
3. **Check disk space**: `docker system df`. You need room for the new image
   (plus the OLD image, until rollback is no longer needed) and for the backup.
4. **Take a pre-upgrade dump** — mandatory:

   ```bash
   just db-backup
   ```

   Or directly:

   ```bash
   docker compose run --no-tty --rm --no-deps backup /usr/local/bin/backup.sh
   ```

5. **Verify the dump** exists and is non-empty:

   ```bash
   ls -lh backups/argus_*.sql.gz*
   ```

   Backups are written by the backup container as root — manage them with
   `sudo`, or `sudo chown -R "$(id -u):$(id -g)" "$BACKUP_DIR"` afterwards.
6. **Copy the backup off-box** (`scp`, `rsync`, object storage). If the server
   itself is affected by the incident, an on-server backup may be unreachable.

## Upgrade procedure

```bash
cd argus-sbomguard
git pull                                          # if running from a checkout
# edit .env: set APP_VERSION to the new release tag
docker compose pull
docker compose up -d
```

Watch the `app` logs for the migration step:

```bash
docker compose logs -f app
```

Expected sequence: `Running database migrations...` then `Migrations complete.`

!!! danger "Migration failure signal"
    If migrations fail on all 10 retries, the entrypoint logs
    `Migration failed after 10 attempts, continuing anyway` and **starts the app
    anyway on an un-migrated schema**. This is not a healthy state — the new
    code runs against the old schema, so the release is not actually live.
    Treat it as an immediate [rollback](#when-to-roll-back) trigger.

## Migration verification

After the app restarts, confirm the upgrade actually landed:

| Check | Command | Expected |
|-------|---------|----------|
| Migrations applied | `docker compose logs app` | `Migrations complete.` |
| Schema is at head | `docker compose exec app alembic current` | The head expected for the release you installed (compare with the release notes) |
| All services up | `docker compose ps` | `app`, `worker`, `scheduler`, `postgres`, `proxy` healthy |
| Readiness | `curl -sS -o /dev/null -w "%{http_code}\n" https://<domain>/readyz` | `200` |
| Data survived | `docker compose exec -T postgres psql -U argus argus -c "select count(*) from projects;"` | Count matches the pre-upgrade expectation |
| Background tasks | `docker compose logs worker` | No scan task errors after the restart |

Finish with a smoke test in the UI: sign in, open a project, and inspect an SBOM
detail page. The old code is gone at this point — if anything misbehaves, roll
back (below) rather than trying to patch a running deployment.

## Rollback procedure

### When to roll back

- App logs show `Migration failed after 10 attempts, continuing anyway`.
- The app is healthy but a feature is broken or behaves differently than
  documented for the new release.
- `worker` logs show task failures after the upgrade.
- Data appears missing or corrupted.

### Path A — Restore from the pre-upgrade backup (recommended)

Works for any migration, including irreversible ones, because it restores the
exact pre-upgrade schema **and** data.

```bash
docker compose stop app worker scheduler   # free database connections

# 1) Revert APP_VERSION in .env to the previous release tag
#    BEFORE restarting, or the entrypoint re-applies `alembic upgrade head`
#    on next boot and re-creates the problem.

# 2) Restore the pre-upgrade dump (drops and recreates the database)
just db-restore argus_<pre_upgrade_timestamp>.sql.gz --reset

# 3) Start the stack with the OLD image
docker compose up -d
```

1. Verify the rollback: sign in, open a project, and confirm row counts match
   the pre-upgrade state (`select count(*) from projects;` etc.).
2. Run another `just db-backup` so the restored state is captured by the
   retention-pruned set — the pre-upgrade dump is now the baseline.

!!! warning "Data loss window"
    Anything written **after** the pre-upgrade dump is lost by this procedure
    (new projects, SBOMs, scan results). That is the price of a clean rollback.
    If you only need to undo the schema, consider
    [Path B](#path-b-alembic-downgrade-best-effort-schema-only) first.

### Path B — `alembic downgrade` (best-effort, schema-only)

Only appropriate when the failing migration is **reversible** and the previous
release can run against the downgraded schema. It reverts the *schema*; it does
not guarantee the *data* still satisfies the old constraints.

If the release shipped more than one migration, step down one revision at a
time until `alembic current` shows the previous release's head:

```bash
docker compose exec app alembic downgrade -1   # repeat until the previous head
docker compose exec app alembic current
```

Then **revert `APP_VERSION` in `.env` to the previous tag before starting the
app again** — otherwise the entrypoint runs `alembic upgrade head` on next boot
and re-applies the migration you just rolled back.

!!! warning "Limitations"
    - The downgrade bodies are exercised only manually — they are
      `# pragma: no cover` in the test suite and have not been validated against
      real production data.
    - A data-affecting downgrade may fail if rows written under the new schema
      cannot satisfy the old constraints. Inspect the migration file
      (`app/migrations/versions/`) before relying on it.
    - Future migrations may be written without a usable downgrade at all.

### After a rollback

- Confirm the previous release's features work end-to-end.
- Take a fresh backup (`just db-backup`) and note in your incident log which
  pre-upgrade dump was restored and why.
- Re-attempt the upgrade only after the root cause is fixed (a corrected
  migration, not a re-run of the same failing one).

## CI upgrade check (TBD)

Planned, not yet implemented: a CI workflow that proves a database can move from
the previous release's schema to the current one. Sketch of the check:

1. Start a fresh PostgreSQL 18.
2. Check out the previous release's migrations and apply them to `head`.
3. Seed representative rows (projects, services, SBOMs, notifications,
   snapshots).
4. Apply the current release's migrations (`alembic upgrade head`).
5. Assert the upgrade succeeds **and** the seeded rows survive.

This catches migrations that are accidentally destructive or that assume a
schema shape that no longer exists. Tracked as a follow-up; the current suite
only exercises migrations on a brand-new database.

## Appendix — Assessing migration reversibility

Whether a migration can be rolled back with `alembic downgrade`
([Path B](#path-b-alembic-downgrade-best-effort-schema-only)) depends on the
specific migration:

- **Check the release notes** — releases document which migrations are
  destructive or irreversible.
- **Read the migration file** (`app/migrations/versions/NNNN_*.py`): the
  `upgrade()`/`downgrade()` pair shows exactly what changes. A downgrade that
  only drops columns/functions or reverts types is usually safe; one that
  transforms data may fail or lose data under the old constraints.
- **Assume nothing across releases** — the chain is not stable before the first
  stable release (see [Pre-stable migration chain](#pre-stable-migration-chain)),
  so revision numbers in one release may not exist in the next.

The downgrade path only matters for [Path B](#path-b-alembic-downgrade-best-effort-schema-only).
For rollback of any migration, [Path A](#path-a-restore-from-the-pre-upgrade-backup-recommended)
is always safe.
