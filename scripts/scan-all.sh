#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${COMPOSE_FILE:=docker-compose.development.yml}"
export COMPOSE_FILE

command -v jq >/dev/null 2>&1 || { echo >&2 "jq is required but not installed"; exit 1; }
command -v syft >/dev/null 2>&1 || { echo >&2 "syft is required but not installed"; exit 1; }

mkdir -p sboms

timestamp=$(date +%Y%m%d_%H%M%S)

echo "Scanning compose images..."

images=$(docker compose images --format json | jq -r '.[] | "\(.Repository):\(.Tag)"' | sort -u)

if [ -z "$images" ]; then
    echo >&2 "No images found — run 'docker compose build' or 'docker compose pull' first"
    exit 1
fi

while IFS= read -r img; do
    echo "  $img"
    name=$(echo "$img" | tr '/:' '_')
    syft "$img" -o cyclonedx-json > "sboms/${name}_${timestamp}.json"
done <<< "$images"
