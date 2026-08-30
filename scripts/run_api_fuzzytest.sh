#!/bin/sh
# API fuzzy test runner — runs inside the standalone test stack app container
# (docker-compose.test.yml). Targets the throwaway test database, never the
# dev data: migrations are applied, an API key is minted and the app is started
# against the isolated test postgres. Mirrors .github/workflows/api-fuzzytest.yml.
set -eu

# alembic.ini hardcodes the dev URL (@postgres); inject the one from the
# environment (POSTGRES_*) so this works in the compose test stack (host
# postgres) and in CI (host localhost) alike.
python3 -c "from alembic import command, config; c = config.Config('alembic.ini'); c.set_main_option('sqlalchemy.url', __import__('config').settings.database_url); command.upgrade(c, 'head')"

ARGUS_API_KEY="$(python3 /scripts/create_api_key.py fuzzy-test)"

uvicorn main:app --host 0.0.0.0 --port 8000 --log-level warning &
UV_PID=$!
trap 'kill "$UV_PID" 2>/dev/null || true' EXIT

for i in $(seq 1 60); do
    if python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz')" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done

if [ "${ready:-0}" -ne 1 ]; then
    echo "app did not become ready in 60s" >&2
    exit 1
fi

schemathesis run \
    --checks all \
    --exclude-checks negative_data_rejection,positive_data_acceptance,unsupported_method,allow_header_conformance \
    --warnings off \
    --max-failures 5 \
    --header "X-API-Key:$ARGUS_API_KEY" \
    http://127.0.0.1:8000/api/openapi.json
