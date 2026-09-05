# Secrets Management

Argus reads its configuration from **environment variables**, which in the
Docker Compose world come from `.env` (via `env_file: .env` on the remote
stack). This page lists every secret, explains the three ways to store and
inject them — `.env`, **Docker secrets**, **Kubernetes Secrets** — and how to
rotate them.

## The secrets

| Variable | What it protects | Default in `.env.example` |
|----------|------------------|---------------------------|
| `SECRET_KEY` | Session cookie signing. The app **refuses to start** in non-development if left at the default | `change-me-to-a-random-secret` |
| `POSTGRES_PASSWORD` | Database access | `argus` |
| `RABBITMQ_PASSWORD` | Broker access | `argus` |
| `BACKUP_ENCRYPTION_KEY` | Backup encryption (AES-256-CBC) | *(empty)* |
| `SMTP_PASSWORD` | Mailbox used for login codes | *(empty)* |
| `SLACK_WEBHOOK_URL` | Alert channel | *(empty)* |
| `DISCORD_WEBHOOK_URL` | Alert channel | *(empty)* |

Non-secret values with no security impact: `POSTGRES_USER`, `POSTGRES_DB`,
`ADMIN_EMAIL`, `DOMAIN`, `APP_VERSION`, the `*_LIMIT` values, rate limits, and
all `OTEL_*`/`LOG_*` settings. API keys created in the UI are application data
(stored in the database) and are handled by the platform, not by the
environment.

## Option 1 — `.env` (default, recommended for Compose)

The simplest and fully supported path. Generate strong values once:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(24))"   # POSTGRES_PASSWORD
python3 -c "import secrets; print(secrets.token_urlsafe(24))"   # RABBITMQ_PASSWORD
openssl rand -base64 32                                         # BACKUP_ENCRYPTION_KEY
```

Rules:

- `.env` is already **gitignored** — never commit it or copy its contents into
  tracked files, examples, or CI logs.
- Restrict file permissions on the host: `chmod 600 .env`.
- Treat `.env` as DR state: it is not recreated by a rebuild, and losing it
  means regenerating every secret (see [Disaster Recovery](disaster-recovery.md)).
- Generate a **dedicated** `BACKUP_ENCRYPTION_KEY`, independent of
  `SECRET_KEY` (see [Encrypted backups](../deployment.md#encrypted-backups-optional)).

## Option 2 — Docker secrets (Swarm / Compose)

Docker secrets mount secret values as **files** inside the container
(`/run/secrets/<name>`), while Argus reads **environment variables**. The
compose files do not use Docker secrets today, so bridging them needs two
pieces: a compose `secrets:` block and a shim that exports the mounted files
as environment variables before the app starts.

`docker-compose.override.yml` (adds the secret mounts):

```yaml
services:
  app:
    environment:
      SECRET_KEY_FILE: /run/secrets/argus_secret_key
      POSTGRES_PASSWORD_FILE: /run/secrets/argus_postgres_password
      RABBITMQ_PASSWORD_FILE: /run/secrets/argus_rabbitmq_password
      BACKUP_ENCRYPTION_KEY_FILE: /run/secrets/argus_backup_key
    secrets:
      - argus_secret_key
      - argus_postgres_password
      - argus_rabbitmq_password
      - argus_backup_key
  worker:        # same mapping — the worker also connects to DB/RabbitMQ
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/argus_postgres_password
      RABBITMQ_PASSWORD_FILE: /run/secrets/argus_rabbitmq_password
    secrets:
      - argus_postgres_password
      - argus_rabbitmq_password

secrets:
  argus_secret_key:
    file: ./secrets/secret_key
  argus_postgres_password:
    file: ./secrets/postgres_password
  argus_rabbitmq_password:
    file: ./secrets/rabbitmq_password
  argus_backup_key:
    file: ./secrets/backup_key
```

The entrypoint shim (any small wrapper that runs before the real command —
e.g. `entrypoint.sh`). It reads the `*_FILE` variables declared above, so the
override and the shim stay in sync:

```sh
# for each secret mapped via a <NAME>_FILE variable, export the value as <NAME>
for env in $(env | sed -n 's/^\(.*\)_FILE=.*/\1/p'); do
    f=$(eval "echo \"\$${env}_FILE\"")
    [ -f "$f" ] && export "$env"="$(cat "$f")"
done
exec "$@"
```

For a fixed set of secrets the explicit form is easier to follow:

```sh
for v in SECRET_KEY POSTGRES_PASSWORD RABBITMQ_PASSWORD BACKUP_ENCRYPTION_KEY; do
    f="/run/secrets/argus_$(echo "$v" | tr '[:upper:]' '[:lower:]')"
    [ -f "$f" ] && export "$v"="$(cat "$f")"
done
exec "$@"
```

If you use the explicit form, drop the `environment:` blocks from the override
above (the secret mounts alone are enough) — otherwise the `*_FILE` variables
are declared but never read.

Caveats:

- The stock image entrypoint does **not** include this shim — you are
  responsible for wiring it (build your own thin image, or mount a shim).
- The `backup` service and the `postgres`/`rabbitmq` containers also need the
  password, so you either share the secret file mount with them or keep those
  in `.env`. A full Docker-secrets setup means patching **every** service.
- File-based secrets are still plaintext at rest on the host (under
  `./secrets/`); encrypt the directory at rest if that matters to you.

Given these caveats, for a plain Compose deployment **Option 1 (`.env` with
`chmod 600`) is the pragmatic recommendation**; Docker secrets earn their keep
only in Docker Swarm, where they also encrypt secrets at rest.

## Option 3 — Kubernetes Secrets (K8s)

On Kubernetes, Secret objects are the natural fit: inject them as environment
variables with `valueFrom.secretKeyRef`, exactly like the backup `CronJob`
example in [Backups on Kubernetes](../deployment.md#backups-on-kubernetes).

Create the Secret (here from a file, so nothing is printed to the shell
history):

```bash
kubectl create secret generic argus-env \
  --from-literal=SECRET_KEY="$(cat secret_key)" \
  --from-literal=POSTGRES_PASSWORD="$(cat postgres_password)" \
  --from-literal=RABBITMQ_PASSWORD="$(cat rabbitmq_password)" \
  --from-literal=BACKUP_ENCRYPTION_KEY="$(cat backup_key)"
```

Deployment snippet:

```yaml
containers:
  - name: app
    image: ghcr.io/trottomv/argus-sbomguard:<release-tag>
    env:
      - name: SECRET_KEY
        valueFrom:
          secretKeyRef:
            name: argus-env
            key: SECRET_KEY
      - name: POSTGRES_PASSWORD
        valueFrom:
          secretKeyRef:
            name: argus-env
            key: POSTGRES_PASSWORD
      # RABBITMQ_PASSWORD, BACKUP_ENCRYPTION_KEY: same pattern
    envFrom:
      - configMapRef:
          name: argus-public-config   # non-secret settings (DOMAIN, APP_VERSION, *_LIMIT, ...)
```

Pointers:

- Put **non-secret** settings in a `ConfigMap` (`envFrom`) and keep only real
  secrets in the `Secret` — cleaner diffs and smaller blast radius.
- The `worker` and `scheduler` pods need `POSTGRES_PASSWORD` and
  `RABBITMQ_PASSWORD` too (they share the image).
- Keep secrets **unencrypted in etcd only if you accept the risk** — enable
  [Encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
  for Secret objects, or use a sealed-secrets / external-secrets flow so the
  manifest never contains plaintext.
- In the same spirit, the `argus-db` Secret for the backup `CronJob` and the
  `argus-env` Secret should share the same `POSTGRES_PASSWORD` source of truth.

## Rotation

A `SECRET_KEY` rotation signs everyone out (they re-login with email) but does
not lose data. Password rotation needs the downstream service to accept the new
value **before** the old one stops working:

1. **Database**: set the new `POSTGRES_PASSWORD` in `.env`, restart
   `postgres`, then restart the app/worker/backup containers so they connect
   with the new password. There is no multi-password support — plan for a brief
   connectivity blip, or use `ALTER USER ... PASSWORD` followed by a rolling
   update of the dependent services.
2. **RabbitMQ**: change `RABBITMQ_PASSWORD`, recreate `rabbitmq`, then restart
   app/worker/scheduler. Queued tasks in RabbitMQ are lost on recreate — a
   clean restart is expected behaviour.
3. **Backups**: changing `BACKUP_ENCRYPTION_KEY` only affects backups written
   **after** the change — old `.enc` files still need the old key, so keep a
   copy of the previous key until the retention window passes.

After any rotation, run a `just db-backup` and verify a restore on a staging
copy before relying on it (see the [DR drill](disaster-recovery.md#the-dr-drill)).
