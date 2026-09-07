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

## Periodic Rescan

New vulnerabilities are published daily, so the latest SBOM of **every service of
every project** is automatically rescanned by Celery Beat on a configurable interval
(`VULN_RESCAN_INTERVAL_SECONDS` in `.env`, default 12h). Each rescan:

- Adds any newly published CVEs to the SBOM
- Refreshes severity/summary/CVSS metadata from the latest Grype data
- Retires findings Grype no longer reports (marked `fixed`), so counts stay current
  even without uploading a new SBOM

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

Open findings are **"actionable"** unless a risk acceptance covers them — an
accepted vulnerability is excluded from the active list, dashboard/summary
counts, snapshots and alerting, but stays visible through the acceptances API.

## Exploit likelihood (EPSS)

Each vulnerability stores the [EPSS](https://www.first.org/epss/) score and
percentile published by Grype when available (`epss_score`,
`epss_percentile`). They are refreshed on every scan and exposed by the
`/api/v1/vulnerabilities/active` API, the MCP `list_vulnerabilities` tool and
the `epss_score` sort option.

## Risk acceptance ("won't fix")

A risk acceptance records a deliberate "won't fix" decision for a
vulnerability, scoped like the finding itself:

- **project scope** (`service_id` omitted): covers every finding of the project,
  including those inside its services;
- **service scope** (`service_id` set): covers the findings of that service only.

```bash
# Accept a vulnerability at project scope
curl -X POST http://localhost:8000/api/v1/vulnerabilities/acceptances \
  -H "Authorization: Bearer argus_xxx" \
  -H "Content-Type: application/json" \
  -d '{"project_id": "...", "vulnerability_id": "...", "reason": "no fix upstream"}'

# List acceptances (optionally per project)
curl "http://localhost:8000/api/v1/vulnerabilities/acceptances?project_id=..." \
  -H "Authorization: Bearer argus_xxx"

# Revert an acceptance (the finding becomes actionable again)
curl -X DELETE http://localhost:8000/api/v1/vulnerabilities/acceptances/{id} \
  -H "Authorization: Bearer argus_xxx"
```

`reason` is required and the same (project, service, vulnerability) scope can
only be accepted once. Reverts are immediate: the vulnerability returns to the
active list, counts and alerting on the next check.

## Per-Project Dashboard

The project detail page shows:

- **Count by severity** — Critical / High / Medium / Low breakdown
- **Trend chart** — Daily snapshots tracking vulnerability counts over time
- **SBOM history** — Each SBOM with its dependency and vulnerability counts

## API

```bash
# List active vulnerabilities
curl "http://localhost:8000/api/v1/vulnerabilities/active?severity=critical&project_id={id}" \
  -H "Authorization: Bearer argus_xxx"

# Get vulnerability details
curl "http://localhost:8000/api/v1/vulnerabilities/{id}" \
  -H "Authorization: Bearer argus_xxx"

# Get daily snapshots for a project
curl "http://localhost:8000/api/v1/vulnerabilities/snapshots?project_id={id}&days=30" \
  -H "Authorization: Bearer argus_xxx"
```

## Severity Order

Vulnerabilities are classified with the following priority:

```
critical > high > medium > low
```

CVSS scores are also stored when available from the vulnerability source.
