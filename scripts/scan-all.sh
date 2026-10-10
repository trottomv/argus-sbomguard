#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${COMPOSE_FILE:=docker-compose.development.yml}"
export COMPOSE_FILE
# Pin the Syft container image so SBOMs are reproducible across runs.
: "${SYFT_VERSION:=v1.54.1}"

command -v jq >/dev/null 2>&1 || { echo >&2 "jq is required but not installed"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo >&2 "docker with the compose plugin is required"; exit 1; }

mkdir -p sboms

timestamp=$(date +%Y%m%d_%H%M%S)

echo "Scanning compose images..."

images=$(docker compose images --format json | jq -r '.[]? | "\(.Repository):\(.Tag)"' | sort -u)

if [ -z "$images" ]; then
    echo >&2 "No images found — run 'docker compose build' or 'docker compose pull' first"
    exit 1
fi

while IFS= read -r img; do
    echo "  $img"
    name=$(echo "$img" | tr '/:' '_')
    # Run Syft in a container so no host install is needed. Mounting the Docker
    # socket lets it read the locally built/pulled images (root-equivalent host
    # access — only run on trusted machines). Capture stdout and write only on
    # success (avoids empty files on failure).
    sbom=$(docker run --rm \
        --volume /var/run/docker.sock:/var/run/docker.sock \
        "anchore/syft:${SYFT_VERSION}" \
        "$img" -o cyclonedx-json)
    printf '%s\n' "$sbom" > "sboms/${name}_${timestamp}.json"
done <<< "$images"

echo "SBOMs written to sboms/"
