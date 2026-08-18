#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Honour the deployed stack: configuration is read from .env when present (docker
# compose does this automatically; the script must agree on the stack and keys).
# Only these keys are consumed, the file is never sourced.
if [ -f .env ]; then
    while IFS='=' read -r key value; do
        case "$key" in
            COMPOSE_FILE|BACKUP_ENCRYPTION_KEY)
                value="${value//\"/}"
                value="${value//$'\r'/}"
                if [ "${!key+x}" != x ] && [ -n "$value" ]; then
                    export "$key=$value"
                fi
                ;;
        esac
    done < .env
fi
: "${COMPOSE_FILE:=docker-compose.development.yml}"
export COMPOSE_FILE

usage() {
    echo "Usage: $0 <backup-file> [--reset]"
    echo
    echo "Restore a PostgreSQL backup created by scripts/backup.sh."
    echo
    echo "  <backup-file>  .sql, .sql.gz or encrypted .sql.gz.enc backup to restore"
    echo "  --reset        drop and recreate the database before restoring"
    echo "                 (required when the database already exists, e.g. during"
    echo "                 a restore drill or after a failed restore)"
    echo
    echo "Encrypted backups require BACKUP_ENCRYPTION_KEY set in .env (and the app"
    echo "image present) — decryption runs in a throwaway app container, so it also"
    echo "works after the stack has been stopped."
    echo
    echo "Stop the app, worker and scheduler first, or the restore fails with"
    echo "'database is being accessed by other users'."
}

if [ "$#" -lt 1 ]; then
    usage
    exit 1
fi

backup_file="$1"
shift

reset=0
for arg in "$@"; do
    case "$arg" in
        --reset) reset=1 ;;
        *) echo >&2 "Unknown option: $arg"; echo; usage; exit 1 ;;
    esac
done

if [ ! -f "$backup_file" ]; then
    echo >&2 "Backup file not found: $backup_file"
    exit 1
fi

command -v docker >/dev/null 2>&1 || { echo >&2 "docker is required but not installed"; exit 1; }

if [[ "$backup_file" == *.enc ]] && [ -z "${BACKUP_ENCRYPTION_KEY:-}" ]; then
    echo >&2 "BACKUP_ENCRYPTION_KEY is required to restore an encrypted backup"
    exit 1
fi

# psql, gunzip and gzip run inside the postgres container; openssl decryption
# runs in a throwaway app container (docker compose run), so it also works after
# the stack was stopped for the restore. The host only needs docker.
if [ "$reset" -eq 1 ]; then
    echo "Resetting database (drop + recreate)..."
    docker compose exec -T postgres sh -c 'set -o pipefail; psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS \"$POSTGRES_DB\"" -c "CREATE DATABASE \"$POSTGRES_DB\" OWNER \"$POSTGRES_USER\""'
fi

echo "Restoring from $backup_file..."
if [[ "$backup_file" == *.enc ]]; then
    docker compose run --rm --no-deps -T --entrypoint openssl app enc -d -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BACKUP_ENCRYPTION_KEY < "$backup_file" \
        | docker compose exec -T postgres sh -c 'set -o pipefail; gunzip -c | psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1'
elif [[ "$backup_file" == *.gz ]]; then
    docker compose exec -T postgres sh -c 'set -o pipefail; gunzip -c | psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' < "$backup_file"
else
    docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' < "$backup_file"
fi

echo "Restore complete."
