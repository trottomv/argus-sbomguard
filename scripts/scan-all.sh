#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p sboms

echo "Scanning remote images..."
images=$(python3 -c "
import yaml, sys
with open('docker-compose.yml') as f:
    doc = yaml.safe_load(f)
for svc in doc.get('services', {}).values():
    img = svc.get('image')
    if img:
        print(img)
")

while IFS= read -r img; do
    echo "  $img"
    name=$(echo "$img" | tr '/:' '_')
    syft "$img" -o cyclonedx-json > "sboms/${name}.json"
done <<< "$images"

echo "Scanning app (local build)..."
docker compose build app -q
img_id=$(docker compose images -q app)
syft "$img_id" -o cyclonedx-json > sboms/app.json
echo "  local -> sboms/app.json"

echo ""
echo "Summary:"
for f in sboms/*.json; do
    name=$(basename "$f" .json)
    pkgs=$(python3 -c "import json; print(len(json.load(open('$f'))['components']))")
    echo "  $name -> $pkgs packages"
done
