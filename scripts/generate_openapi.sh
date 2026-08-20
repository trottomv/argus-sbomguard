#!/usr/bin/env bash
set -euo pipefail

# Regenerate docs/api/openapi.json from a running instance.
#
# The schema mirrors the live contract exactly — run this whenever the API
# changes and commit the result. Requires an instance reachable at the URL
# below (e.g. `docker compose up -d` or the local dev server).
#
# Usage: scripts/generate_openapi.sh
#
# Override the target with ARGUS_API_URL, e.g.:
#   ARGUS_API_URL=http://localhost:8000 scripts/generate_openapi.sh

cd "$(dirname "$0")/.."

: "${ARGUS_API_URL:=http://localhost:8000}"

command -v jq >/dev/null 2>&1 || { echo >&2 "jq is required but not installed"; exit 1; }

url="$ARGUS_API_URL/api/openapi.json"

echo "Fetching $url ..."
# Normalize (reindent) so diffs stay readable and stable.
curl -fsS "$url" | jq . > docs/api/openapi.json

echo "docs/api/openapi.json updated"
