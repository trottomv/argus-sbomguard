# AI Agents (MCP)

Argus exposes a **read-only** [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server so AI agents (opencode, Claude Code, Cursor, ...) can inspect your
projects, SBOMs and vulnerability posture with natural-language queries — without
ever triggering a scan, rescan or upload.

The endpoint is served by the existing app process at `/api/v1/mcp` (Streamable
HTTP transport); no extra container is required.

## Quick start

```bash
# 1. Enable the endpoint in .env and restart the app
#    MCP_ENABLED=true
docker compose up -d --build app

# 2. Create an API key for the agent
docker compose exec app python /app/scripts/create_api_key.py mcp-agent

# 3. Sanity-check the endpoint (expect HTTP 200, Content-Type text/event-stream)
curl -i -X POST http://localhost:8000/api/v1/mcp \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api-key>" \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'

# 4. Point opencode / Claude Code at http://localhost:8000/api/v1/mcp
#    (or https://<host>/api/v1/mcp in production) with the bearer header
```

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
  loopback hosts, your configured `DOMAIN`, and the **exact hostnames** listed
  in `ALLOWED_HOSTS` (each as the bare hostname and as `host:<port>`, so
  requests proxied through Caddy on the default ports work). Any other `Host`
  header is rejected with `421`. If you reach Argus through a proxy on a
  hostname not covered above, add it — e.g. `ALLOWED_HOSTS=argus.example.com`.
  Subdomain wildcards (`*.example.com`) cannot be enforced on the MCP endpoint;
  use exact hostnames there.

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
      "type": "remote",
      "url": "https://argus.example.com/api/v1/mcp",
      "oauth": false,
      "headers": {
        "Authorization": "Bearer ${ARGUS_API_KEY}"
      }
    }
  }
}
```

`oauth: false` is required so opencode does not try the OAuth auto-discovery
flow; with an API key server, the bearer header alone is enough. Restart
opencode after editing the config, then check with `opencode mcp list` /
`opencode mcp debug argus`.

Replace `ARGUS_API_KEY` with the raw key (export it in your shell/environment,
or inline the value for local experimentation).

## Operational notes

- The endpoint is long-lived SSE for the Streamable HTTP transport; make sure
  your reverse proxy (Caddy + Coraza) does not time out or rewrite the
  `Authorization` header for `/api/v1/mcp`.
- API keys are the only credential type accepted, so access is independently
  revocable without logging out human sessions.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `404` when probing the endpoint | `MCP_ENABLED` not set (default `false`) | Set `MCP_ENABLED=true` in `.env` and restart the app |
| `401` with `{"detail": "Bearer token required"}` | Missing or non-bearer `Authorization` header | Send `Authorization: Bearer <api-key>`; the opencode key is the raw `argus_...` string, not an OAuth token |
| `401` with `{"detail": "Invalid API key"}` / `"API key expired"` | Unknown or expired key | Create a fresh key via the Settings page or `create_api_key.py` |
| `421` (only when `ALLOWED_HOSTS` is pinned) | `Host` header not in the allow-list | Add the exact hostname you connect to, e.g. `ALLOWED_HOSTS=argus.example.com` (bare hostname and ported forms are accepted) |
| "SSE error invalid content type" in opencode | opencode reached the endpoint but got a non-SSE response — typically a `404` (endpoint disabled) or `401` (missing/invalid key) on the first request | Confirm the curl handshake in Quick start succeeds first, then fix the config (`.env` / header / URL) and restart opencode |
| Tools load but opencode starts an OAuth browser flow | OAuth auto-detection enabled | Add `"oauth": false` and the `Authorization` header to the opencode config |
