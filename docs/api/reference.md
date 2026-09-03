# API Reference

The `/api/v1` contract is **frozen** for the current major version. See the
[Versioning & Deprecation Policy](versioning.md) for stability guarantees,
deprecation rules, and removal timelines.

The machine-readable OpenAPI schema is served at `/api/openapi.json`
([committed copy](openapi.json) for offline browsing). Browse it in the docs at
[ReDoc](http://localhost:8000/api/docs).

## Authentication

All `/api/v1/*` endpoints require an API key passed via the `Authorization: Bearer` header:

```bash
curl -H "Authorization: Bearer argus_xxxxxxxxxxxx" http://localhost:8000/api/v1/...
```

gRPC endpoints require the `authorization: bearer` metadata header.

## REST API Endpoints

### Projects

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/projects` | List projects (paginated, filterable) |
| `POST` | `/api/v1/projects` | Create project |
| `GET` | `/api/v1/projects/{id}` | Get project details |
| `PATCH` | `/api/v1/projects/{id}` | Update project |
| `DELETE` | `/api/v1/projects/{id}` | Delete project and cascade |

Project responses include a `slug` field — a stable, readable identifier
generated from the project name (e.g. `Argus SBOM Guard` → `argus-sbom-guard`).

### SBOMs

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/sboms/upload` | Upload SBOM file (multipart) — by project UUID or slug |
| `GET` | `/api/v1/sboms/{id}` | Get SBOM with deps + vulns |
| `GET` | `/api/v1/sboms/{id}/download` | Download raw SBOM JSON |
| `GET` | `/api/v1/sboms/{id}/diff/{other_id}` | Diff two SBOM versions |
| `DELETE` | `/api/v1/sboms/{id}` | Delete SBOM |

`POST /api/v1/sboms/upload` targets a project by **exactly one** of
`project_id` (UUID) or `slug`:

### Services

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/services` | List services for a project (`project_id` required) |
| `DELETE` | `/api/v1/services/{id}` | Delete service |

### Vulnerabilities

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/vulnerabilities/active` | List active (open) vulns |
| `GET` | `/api/v1/vulnerabilities/summary` | Vulnerability counts by severity |

### Alert Rules

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/alert-rules` | List alert rules |
| `POST` | `/api/v1/alert-rules` | Create alert rule |
| `PATCH` | `/api/v1/alert-rules/{id}` | Update alert rule |
| `DELETE` | `/api/v1/alert-rules/{id}` | Delete alert rule |

## Pagination

Paginated endpoints accept `page` and `per_page` query parameters:

```bash
curl "http://localhost:8000/api/v1/projects?page=1&per_page=20" \
  -H "Authorization: Bearer argus_xxx"
```

Response includes:

```json
{
  "items": [...],
  "total": 42,
  "page": 1,
  "per_page": 20,
  "total_pages": 3,
  "has_more": true
}
```

## Filtering & Sorting

Most list endpoints support:

- **`sort`**: Column to sort by (varies per resource)
- **`order`**: `asc` or `desc`
- **`project_id`**: Filter by project
- **`service_id`**: Filter by service
- **`severity`**: Filter vulnerabilities by severity

Example:

```bash
curl "http://localhost:8000/api/v1/sboms?sort=uploaded_at&order=desc&project_id={id}" \
  -H "Authorization: Bearer argus_xxx"
```

## gRPC

The SBOM upload gRPC service is defined in `protos/sbom.proto` and served on port 50051.

```protobuf
service SBOMService {
  rpc UploadSBOM (UploadSBOMRequest) returns (UploadSBOMResponse);
}
```

Use [grpcurl](https://github.com/fullstorydev/grpcurl) for testing:

```bash
grpcurl -plaintext \
  -H 'authorization: bearer argus_xxx' \
  localhost:50051 list
```
