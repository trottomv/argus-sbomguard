#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Honour the deployed stack: configuration is read from .env when present (docker
# compose does this automatically; the script must agree on the stack and keys).
# Only these keys are consumed, the file is never sourced.
if [ -f .env ]; then
    while IFS='=' read -r key value; do
        case "$key" in
            COMPOSE_FILE|BACKUP_DIR|BACKUP_RETENTION|BACKUP_ENCRYPTION_KEY)
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

BACKUP_DIR="${BACKUP_DIR:-backups}"
BACKUP_RETENTION="${BACKUP_RETENTION:-7}"

command -v docker >/dev/null 2>&1 || { echo >&2 "docker is required but not installed"; exit 1; }

if ! [[ "$BACKUP_RETENTION" =~ ^[0-9]+$ ]]; then
    echo >&2 "BACKUP_RETENTION must be a non-negative integer, got '$BACKUP_RETENTION'"
    exit 1
fi

if [ -n "${BACKUP_ENCRYPTION_KEY:-}" ]; then
    ENCRYPTION_ENABLED=1
else
    ENCRYPTION_ENABLED=0
fi

mkdir -p "$BACKUP_DIR"

timestamp=$(date +%Y%m%d_%H%M%S)
if [ "$ENCRYPTION_ENABLED" -eq 1 ]; then
    backup_file="${BACKUP_DIR}/argus_${timestamp}.sql.gz.enc"
else
    backup_file="${BACKUP_DIR}/argus_${timestamp}.sql.gz"
fi

# pg_dump and gzip run inside the postgres container; openssl encryption inside
# the app container (invoked directly, not via sh, so it also works on the
# remote image where /bin/sh is removed). The host only needs docker.
echo "Dumping database to $backup_file..."
if [ "$ENCRYPTION_ENABLED" -eq 1 ]; then
    if ! docker compose exec -T postgres sh -c 'set -o pipefail; pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip' \
        | docker compose exec -T app openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BACKUP_ENCRYPTION_KEY \
        > "$backup_file"; then
        echo >&2 "Backup failed; removing incomplete file"
        rm -f "$backup_file"
        exit 1
    fi
else
    if ! docker compose exec -T postgres sh -c 'set -o pipefail; pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip' > "$backup_file"; then
        echo >&2 "Backup failed; removing incomplete file"
        rm -f "$backup_file"
        exit 1
    fi
fi

if [ ! -s "$backup_file" ]; then
    echo >&2 "Backup failed: empty output"
    rm -f "$backup_file"
    exit 1
fi

if [ "$ENCRYPTION_ENABLED" -eq 1 ]; then
    if ! docker compose exec -T app openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BACKUP_ENCRYPTION_KEY < "$backup_file" \
        | docker compose exec -T postgres sh -c 'gzip -t'; then
        echo >&2 "Backup failed: could not decrypt or verify archive"
        rm -f "$backup_file"
        exit 1
    fi
else
    if ! docker compose exec -T postgres sh -c 'gzip -t' < "$backup_file"; then
        echo >&2 "Backup failed: not a valid gzip archive"
        rm -f "$backup_file"
        exit 1
    fi
fi

size=$(du -h "$backup_file" | cut -f1)
echo "Backup complete: $backup_file ($size)"

if [ "$BACKUP_RETENTION" -gt 0 ]; then
    shopt -s nullglob
    backups=("$BACKUP_DIR"/argus_*.sql.gz*)
    if [ "${#backups[@]}" -gt "$BACKUP_RETENTION" ]; then
        printf '%s\n' "${backups[@]}" | sort -r | tail -n +"$((BACKUP_RETENTION + 1))" | while IFS= read -r old; do
            echo "Pruning old backup: $old"
            rm -f "$old"
        done
    fi
fi
