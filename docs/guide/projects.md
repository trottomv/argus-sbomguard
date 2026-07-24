# Projects

Projects are the top-level organizational unit in Argus SBOM Guard.
Each project groups services, SBOMs, and vulnerability data.

## Creating a Project

**UI**: Dashboard → Projects → New Project

**API**:

```bash
curl -X POST http://localhost:8000/api/v1/projects \
  -H "X-API-Key: argus_xxx" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-app", "description": "My application", "repo_url": "https://github.com/org/my-app"}'
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `name` | Yes | string | Unique project name |
| `description` | No | string | Project description |
| `repo_url` | No | string | Git repository URL |
| `platform` | No | string | Platform identifier (e.g. `github`, `gitlab`) |

## Viewing a Project

From the dashboard, click any project to see:

- **Services** — Microservices/containers in this project
- **SBOM History** — All uploaded SBOMs with dependency counts and timestamps
- **Vulnerability Summary** — Open vulnerabilities by severity
- **Trend Chart** — Daily vulnerability snapshots over time

## Updating a Project

**API**:

```bash
curl -X PATCH http://localhost:8000/api/v1/projects/{id} \
  -H "X-API-Key: argus_xxx" \
  -H "Content-Type: application/json" \
  -d '{"description": "Updated description"}'
```

## Deleting a Project

Deleting a project removes all associated services, SBOMs, vulnerabilities, and alert configs.

!!! warning
    This action is irreversible.
