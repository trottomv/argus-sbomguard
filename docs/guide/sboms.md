# SBOMs

Argus SBOM Guard supports CycloneDX and SPDX JSON formats.

## Uploading an SBOM

**UI**: Navigate to a project → Upload SBOM

**REST API**:

```bash
curl -X POST http://localhost:8000/api/v1/sboms/upload \
  -H "Authorization: Bearer argus_xxx" \
  -F "project_id=00000000-0000-0000-0000-000000000001" \
  -F "version=1.2.3" \
  -F "service_name=api-gateway" \
  -F "file=@sbom.json"
```

You can target the project by UUID (`project_id`) or by its readable **slug**
(`slug`) — provide exactly one:

```bash
curl -X POST http://localhost:8000/api/v1/sboms/upload \
  -H "Authorization: Bearer argus_xxx" \
  -F "slug=my-project" \
  -F "version=1.2.3" \
  -F "file=@sbom.json"
```

**gRPC**:

```bash
grpcurl -plaintext \
  -H 'authorization: bearer argus_xxx' \
  -d '{
    "project_id": "00000000-0000-0000-0000-000000000001",
    "version": "1.2.3",
    "service_name": "api-gateway",
    "format": "cyclonedx",
    "raw_sbom": "..."
  }' \
  localhost:50051 sbom.SBOMService/UploadSBOM
```

| Field | Required | Description |
|-------|----------|-------------|
| `project_id` | Yes* | UUID of the target project |
| `slug` | Yes* | Slug of the target project (alternative to `project_id`) |
| `file` | Yes | JSON SBOM file |
| `version` | No | Software version tag |
| `service_name` | No | Microservice/component name |

\* Provide **exactly one** of `project_id` or `slug`.

## What Happens on Upload

1. The SBOM is parsed and validated
2. Dependencies are extracted and stored
3. A SHA-256 hash is computed for deduplication
4. A Celery task triggers Grype vulnerability scanning
5. Vulnerabilities are reconciled across SBOM versions

## Downloading an SBOM

```bash
curl -X GET http://localhost:8000/api/v1/sboms/{id}/download \
  -H "Authorization: Bearer argus_xxx" \
  -o sbom.json
```

## Getting SBOM Details

```bash
curl http://localhost:8000/api/v1/sboms/{id} \
  -H "Authorization: Bearer argus_xxx"
```

Returns the SBOM metadata, all dependencies, and attached vulnerabilities.

## Diffing Two SBOMs

Compare two SBOM versions to see what dependencies changed:

```bash
curl http://localhost:8000/api/v1/sboms/{id}/diff/{other_id} \
  -H "Authorization: Bearer argus_xxx"
```

Response:

```json
{
  "added": [{"name": "new-lib", "version": "1.0.0"}],
  "removed": [{"name": "old-lib", "version": "0.9.0"}],
  "changed": [{"name": "updated-lib", "from_version": "1.0.0", "to_version": "2.0.0"}]
}
```

## Deleting an SBOM

```bash
curl -X DELETE http://localhost:8000/api/v1/sboms/{id} \
  -H "Authorization: Bearer argus_xxx"
```

Deleting an SBOM re-runs vulnerability reconciliation on the latest remaining SBOM
for that service, reverting fixed vulnerabilities if needed.

## Generating SBOMs

Use [Syft](https://github.com/anchore/syft) to generate CycloneDX SBOMs from
your project. To automate this in your CI/CD, see the
[CI/CD Integration](ci.md) guide:

```bash
syft scan dir:. -o cyclonedx-json > sbom.json
```

Or from a container image:

```bash
syft scan registry:my-app:latest -o cyclonedx-json > sbom.json
```
