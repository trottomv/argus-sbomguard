#!/bin/sh
set -e

# Run migrations only if this is the app service (not the worker)
if [ "$1" = "uvicorn" ]; then
    echo "Running database migrations..."
    retries=0
    max_retries=10
    until alembic upgrade head || [ $retries -eq $max_retries ]; do
        retries=$((retries + 1))
        echo "Migration failed, retrying in 2s ($retries/$max_retries)..."
        sleep 2
    done
    if [ $retries -eq $max_retries ]; then
        echo "Migration failed after $max_retries attempts, continuing anyway..."
    fi
    echo "Migrations complete."
fi

echo "Starting application..."
exec "$@"
