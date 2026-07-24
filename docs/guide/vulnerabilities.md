# Vulnerabilities

Each uploaded SBOM is automatically scanned for vulnerabilities using
[Grype](https://github.com/anchore/grype) and the [OSV API](https://osv.dev).

## Scanning Pipeline

1. SBOM is uploaded → Celery task triggers
2. Grype scans the SBOM against its vulnerability database
3. Results are mapped to dependencies by PURL
4. New vulnerabilities are inserted; existing ones are updated
5. Reconciliation runs: vulnerabilities not found in the latest scan are marked `fixed`
6. Alert rules are checked and notifications sent

## Viewing Vulnerabilities

**UI**: Dashboard → Vulnerabilities

Filter by:

- **Severity**: Critical, High, Medium, Low
- **Project**: Scope to a specific project
- **Service**: Scope to a specific service/component
- **Sort**: By CVSS score, severity, or publication date

## Vulnerability States

| Status | Meaning |
|--------|---------|
| `open` | Vulnerability confirmed in the latest SBOM |
| `fixed` | No longer present in the latest SBOM (auto-reconciled) |

## Per-Project Dashboard

The project detail page shows:

- **Count by severity** — Critical / High / Medium / Low breakdown
- **Trend chart** — Daily snapshots tracking vulnerability counts over time
- **SBOM history** — Each SBOM with its dependency and vulnerability counts

## API

```bash
# List active vulnerabilities
curl "http://localhost:8000/api/v1/vulnerabilities/active?severity=critical&project_id={id}" \
  -H "X-API-Key: argus_xxx"

# Get vulnerability details
curl "http://localhost:8000/api/v1/vulnerabilities/{id}" \
  -H "X-API-Key: argus_xxx"

# Get daily snapshots for a project
curl "http://localhost:8000/api/v1/vulnerabilities/snapshots?project_id={id}&days=30" \
  -H "X-API-Key: argus_xxx"
```

## Severity Order

Vulnerabilities are classified with the following priority:

```
critical > high > medium > low
```

CVSS scores are also stored when available from the vulnerability source.
