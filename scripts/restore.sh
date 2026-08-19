#!/bin/sh
set -eu
# Best-effort pipefail (busybox ash, dash and bash support it; harmless otherwise).
set -o pipefail 2>/dev/null || true

# Ecosystem-agnostic PostgreSQL restore. Pure script: no docker or k8s awareness.
# Runs wherever psql, gunzip and (optionally) openssl are installed — e.g. the
# 'backup' compose service or a k8s Job. Connection comes from DATABASE_URL or
# the libpq PG* variables (PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE).
# --reset drops and recreates the database (no active connections allowed).

usage() {
    cat <<EOF
Usage: $0 <backup-file> [--reset]

Restore a PostgreSQL backup created by backup.sh.

  <backup-file>  .sql, .sql.gz or encrypted .sql.gz.enc backup to restore
  --reset        drop and recreate the database before restoring
                 (required when the database already exists, e.g. during
                 a restore drill or after a failed restore)

Connection comes from DATABASE_URL or the libpq PG* variables. Encrypted
backups require BACKUP_ENCRYPTION_KEY. --reset drops the database, so no
active connections may exist (stop/scale down the app first).
EOF
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
        *) echo "restore: unknown option: $arg" >&2; echo; usage; exit 1 ;;
    esac
done

if [ ! -f "$backup_file" ]; then
    echo "restore: backup file not found: $backup_file" >&2
    exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
    echo "restore: psql is required but not installed" >&2
    exit 1
fi

case "$backup_file" in
    *.enc)
        if [ -z "${BACKUP_ENCRYPTION_KEY:-}" ]; then
            echo "restore: BACKUP_ENCRYPTION_KEY is required to restore an encrypted backup" >&2
            exit 1
        fi
        if ! command -v openssl >/dev/null 2>&1; then
            echo "restore: openssl is required but not installed" >&2
            exit 1
        fi
        ;;
esac

psql_cmd() {
    if [ -n "${DATABASE_URL:-}" ]; then
        psql "$DATABASE_URL" "$@"
    else
        psql "$@"
    fi
}

if [ "$reset" -eq 1 ]; then
    if [ -n "${DATABASE_URL:-}" ]; then
        # Split off the query string so the maintenance URL keeps connection
        # options (e.g. sslmode=require) instead of silently dropping them.
        url="${DATABASE_URL%%\?*}"
        query=""
        case "$DATABASE_URL" in
            *\?*) query="?${DATABASE_URL#*\?}" ;;
        esac
        dbname="${url##*/}"
        maint="${url%/*}/postgres${query}"
        echo "restore: resetting database '$dbname'"
        psql "$maint" -v ON_ERROR_STOP=1 \
            -c "DROP DATABASE IF EXISTS \"$dbname\"" \
            -c "CREATE DATABASE \"$dbname\""
    else
        dbname="${PGDATABASE:-postgres}"
        echo "restore: resetting database '$dbname'"
        psql -d postgres -v ON_ERROR_STOP=1 \
            -c "DROP DATABASE IF EXISTS \"$dbname\"" \
            -c "CREATE DATABASE \"$dbname\""
    fi
fi

# pg_dump resets the search_path to an empty one for restore safety, but SQL
# function bodies that reference extension functions unqualified (e.g. unaccent
# in public.slugify) then fail to inline when a generated column is recreated.
# Re-add public to the search_path right after pg_dump's reset so such functions
# resolve regardless of whether the dump predates schema-qualified references.
SEARCH_PATH_INJECT="s|^SELECT pg_catalog.set_config('search_path', '', false);|&\\nSELECT pg_catalog.set_config('search_path', 'public, pg_catalog', false);|"

echo "restore: restoring from $backup_file"
case "$backup_file" in
    *.enc)
        openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BACKUP_ENCRYPTION_KEY < "$backup_file" \
            | gunzip -c \
            | sed "$SEARCH_PATH_INJECT" \
            | psql_cmd -v ON_ERROR_STOP=1
        ;;
    *.gz)
        gunzip -c "$backup_file" | sed "$SEARCH_PATH_INJECT" | psql_cmd -v ON_ERROR_STOP=1
        ;;
    *)
        sed "$SEARCH_PATH_INJECT" "$backup_file" | psql_cmd -v ON_ERROR_STOP=1
        ;;
esac

echo "restore: complete"
