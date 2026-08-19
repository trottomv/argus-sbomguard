#!/bin/sh
set -eu
# Best-effort pipefail (busybox ash, dash and bash support it; harmless otherwise).
set -o pipefail 2>/dev/null || true

# Ecosystem-agnostic PostgreSQL backup. Pure script: no docker or k8s awareness.
# Runs wherever pg_dump, gzip and (optionally) openssl are installed — e.g. the
# 'backup' compose service or a k8s CronJob. Connection comes from DATABASE_URL
# or the libpq PG* variables (PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE).
# Backups are written to BACKUP_DIR as argus_<timestamp>.sql.gz, encrypted
# (argus_<timestamp>.sql.gz.enc) when BACKUP_ENCRYPTION_KEY is set, with
# BACKUP_RETENTION pruning (0 = keep all).

BACKUP_DIR="${BACKUP_DIR:-backups}"
BACKUP_RETENTION="${BACKUP_RETENTION:-7}"

for cmd in pg_dump gzip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "backup: $cmd is required but not installed" >&2
        exit 1
    fi
done

case "$BACKUP_RETENTION" in
    ''|*[!0-9]*)
        echo "backup: BACKUP_RETENTION must be a non-negative integer, got '$BACKUP_RETENTION'" >&2
        exit 1
        ;;
esac

ENCRYPTION_ENABLED=0
if [ -n "${BACKUP_ENCRYPTION_KEY:-}" ]; then
    ENCRYPTION_ENABLED=1
    if ! command -v openssl >/dev/null 2>&1; then
        echo "backup: openssl is required (BACKUP_ENCRYPTION_KEY set) but not installed" >&2
        exit 1
    fi
fi

mkdir -p "$BACKUP_DIR"

timestamp=$(date +%Y%m%d_%H%M%S)
if [ "$ENCRYPTION_ENABLED" -eq 1 ]; then
    backup_file="$BACKUP_DIR/argus_${timestamp}.sql.gz.enc"
else
    backup_file="$BACKUP_DIR/argus_${timestamp}.sql.gz"
fi

dump() {
    if [ -n "${DATABASE_URL:-}" ]; then
        pg_dump "$DATABASE_URL"
    else
        pg_dump
    fi
}

echo "backup: dumping database to $backup_file"
if [ "$ENCRYPTION_ENABLED" -eq 1 ]; then
    if ! dump | gzip | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BACKUP_ENCRYPTION_KEY > "$backup_file"; then
        echo "backup: failed; removing incomplete file" >&2
        rm -f "$backup_file"
        exit 1
    fi
else
    if ! dump | gzip > "$backup_file"; then
        echo "backup: failed; removing incomplete file" >&2
        rm -f "$backup_file"
        exit 1
    fi
fi

if [ ! -s "$backup_file" ]; then
    echo "backup: failed: empty output" >&2
    rm -f "$backup_file"
    exit 1
fi

if [ "$ENCRYPTION_ENABLED" -eq 1 ]; then
    if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BACKUP_ENCRYPTION_KEY < "$backup_file" | gzip -t; then
        echo "backup: failed: could not decrypt or verify archive" >&2
        rm -f "$backup_file"
        exit 1
    fi
else
    if ! gzip -t < "$backup_file"; then
        echo "backup: failed: not a valid gzip archive" >&2
        rm -f "$backup_file"
        exit 1
    fi
fi

size=$(du -h "$backup_file" | cut -f1)
echo "backup: complete: $backup_file ($size)"

if [ "$BACKUP_RETENTION" -gt 0 ]; then
    # Two passes over the (lexically sorted, oldest-first) glob so filenames
    # are handled verbatim and a missing glob is a no-op.
    total=0
    for f in "$BACKUP_DIR"/argus_*.sql.gz*; do
        [ -e "$f" ] || continue
        total=$((total + 1))
    done
    to_prune=$((total - BACKUP_RETENTION))
    n=0
    for f in "$BACKUP_DIR"/argus_*.sql.gz*; do
        [ -e "$f" ] || continue
        n=$((n + 1))
        if [ "$n" -le "$to_prune" ]; then
            echo "backup: pruning old backup: $f"
            rm -f "$f"
        fi
    done
fi
