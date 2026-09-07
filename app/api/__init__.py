"""REST API routers, versioned by subpackage (api/v1, api/v2, ...).

Unversioned routers live at the package root: the HTML login flow
(api.auth), the backoffice pages (api.pages), the liveness/readiness
endpoints (api.healthchecks) and the MCP endpoint mount (api.mcp_server).
"""
