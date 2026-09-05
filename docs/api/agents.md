# AI Agents (MCP)

Argus exposes a **read-only** [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server so AI agents (opencode, Claude Code, Cursor, ...) can inspect your
projects, SBOMs and vulnerability posture with natural-language queries — without
ever triggering a scan, rescan or upload.

The endpoint is served by the existing app process at `/api/v1/mcp` (Streamable
HTTP transport); no extra container is required.

## Enabling

```dotenv
# .env
MCP_ENABLED=true
```

- Default is `false`: the endpoint responds `404` until you opt in.
- The app validates the `Host` header globally via Starlette's
  `TrustedHostMiddleware`. Leave `ALLOWED_HOSTS=*` (default, allow any host) or
  pin it to your public host, e.g. `ALLOWED_HOSTS=argus.example.com`.
- The MCP endpoint itself always enforces DNS-rebinding protection: it accepts
  loopback hosts and your configured `DOMAIN`, plus the `host:*` patterns
  derived from `ALLOWED_HOSTS`. Any other `Host` header is rejected with `421`.
  If you reach Argus through a proxy on a hostname not covered above, add it —
  e.g. `ALLOWED_HOSTS=argus.example.com`.

## Authentication

MCP clients must authenticate every request with an API key:

```
Authorization: Bearer <api-key>
```

Only the standard bearer header is accepted (no OAuth discovery, no session
cookies). Create a key from the Settings page or the CLI:

```bash
docker compose exec app python /app/scripts/create_api_key.py mcp-agent
```

Responses:

| Case | Status |
|------|--------|
| Missing / malformed / non-bearer header | `401` |
| Unknown key | `401` |
| Expired key | `401` (with `WWW-Authenticate` challenge) |
| Valid key | tool results |

## Tools

| Tool | Description |
|------|-------------|
| `list_projects` | List all projects (name, slug, repo URL, platform). |
| `list_services` | List the services of a project (`project_id`). |
| `list_sboms` | List SBOMs newest-first, optionally filtered by project/service. |
| `get_sbom` | Full SBOM detail: metadata, dependencies, known vulnerabilities. |
| `list_vulnerabilities` | Currently open vulnerabilities, with severity/project/service/CVE filters. |
| `summarize_vulnerabilities` | Platform-wide posture: open counts by severity, affected projects/services, fixed. |
| `get_snapshot` | Daily platform-wide vulnerability snapshot trend (last N days). |
| `list_alerts` | Alert rules (per-project threshold + notification channel). |

All tools return JSON. Unknown identifiers (invalid UUID, missing project or
SBOM) are reported in the payload as `{"error": "..."}`, so agents can react
instead of failing silently.

## Client configuration

Point your MCP HTTP client at `https://<host>/api/v1/mcp` and send the API key
via the `Authorization: Bearer` header. Disable OAuth auto-detection.

**Claude Code** (`.mcp.json`):

```json
{
  "mcpServers": {
    "argus": {
      "type": "http",
      "url": "https://argus.example.com/api/v1/mcp",
      "headers": {
        "Authorization": "Bearer ${ARGUS_API_KEY}"
      }
    }
  }
}
```

**opencode** (`opencode.json`):

```json
{
  "mcp": {
    "argus": {
      "type": "http",
      "url": "https://argus.example.com/api/v1/mcp",
      "headers": {
        "Authorization": "Bearer ${ARGUS_API_KEY}"
      }
    }
  }
}
```

Replace `ARGUS_API_KEY` with the raw key (export it in your shell/environment,
or inline the value for local experimentation).

## Operational notes

- The endpoint is long-lived SSE for the Streamable HTTP transport; make sure
  your reverse proxy (Caddy + Coraza) does not time out or rewrite the
  `Authorization` header for `/api/v1/mcp`.
- API keys are the only credential type accepted, so access is independently
  revocable without logging out human sessions.
