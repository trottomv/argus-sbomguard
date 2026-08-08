# API Reference

Full OpenAPI / Swagger UI available at [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
and ReDoc at [http://localhost:8000/api/redoc](http://localhost:8000/api/redoc).

## Authentication

All `/api/v1/*` endpoints require an API key passed via the `X-API-Key` header:

```bash
curl -H "X-API-Key: argus_xxxxxxxxxxxx" http://localhost:8000/api/v1/...
```

gRPC endpoints require the `api-key` metadata header.

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
generated from the project name (e.g. `Argus SBOM Guard` → `argus-sbomguard`).

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
| `GET` | `/api/v1/services` | List services (paginated) |
| `POST` | `/api/v1/services` | Create service |
| `PATCH` | `/api/v1/services/{id}` | Update service |
| `DELETE` | `/api/v1/services/{id}` | Delete service |

### Vulnerabilities

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/vulnerabilities/active` | List active (open) vulns |
| `GET` | `/api/v1/vulnerabilities/{id}` | Get vulnerability details |
| `GET` | `/api/v1/vulnerabilities/snapshots` | Get daily snapshot data |

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/alerts` | List alert configs |
| `POST` | `/api/v1/alerts` | Create alert config |
| `PATCH` | `/api/v1/alerts/{id}` | Update alert config |
| `DELETE` | `/api/v1/alerts/{id}` | Delete alert config |

### API Keys

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/api-keys` | List API keys |
| `POST` | `/api/v1/api-keys` | Generate new API key |
| `DELETE` | `/api/v1/api-keys/{id}` | Revoke API key |

## Pagination

Paginated endpoints accept `page` and `per_page` query parameters:

```bash
curl "http://localhost:8000/api/v1/projects?page=1&per_page=20" \
  -H "X-API-Key: argus_xxx"
```

Response includes:

```json
{
  "items": [...],
  "total": 42,
  "page": 1,
  "per_page": 20,
  "total_pages": 3
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
  -H "X-API-Key: argus_xxx"
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
  -H 'api-key: argus_xxx' \
  localhost:50051 list
```
