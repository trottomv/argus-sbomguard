# Observability

Argus exposes a Prometheus-compatible `GET /metrics` endpoint and can forward
OpenTelemetry traces to a backend of your choice. The whole stack is centered
on the **OpenTelemetry Collector**, which acts as the observability hub.

## Architecture

```
                     OTLP/HTTP :4318 (optional traces)
Application ──────────────────────►  ┌──────────────────────────┐
  (OTel SDK)                         │      OTel Collector      │
                                     │  ┌────────────────────┐  │
                                     │  │ hostmetrics (/hostfs)│ │
                                     │  │ otlp receiver (4318) │ │
                                     │  │ prometheus exporter  │ │
                                     │  │ otlphttp forward     │ │
                                     │  └────────────────────┘  │
                                     └───────────┬──────────────┘
GET /metrics (Caddy :443 → :9464) ◄──┘           │  OTEL_FORWARD_ENDPOINT
                                                 ▼
                                       Jaeger (optional, local)
                                       or any OTLP backend
```

Key facts:

- **`/metrics` is always active** by default. It is served by the OTel
  Collector (not the application) and exposes **host metrics** scraped from the
  host filesystem mounted at `/hostfs` (CPU, memory, disk, load, network).
- The application never hosts `/metrics`; Prometheus scrapes the Collector's
  `:9464` endpoint through the Caddy reverse proxy.
- **Traces are optional.** Application-level trace export to the Collector is
  disabled unless you enable it (see below).
- There are **two distinct hops**: the app always pushes traces to the in-stack
  Collector (`OTEL_EXPORTER_OTLP_ENDPOINT`, default
  `http://otel-collector:4318/v1/traces`), and the Collector forwards them to
  the final backend (`OTEL_FORWARD_ENDPOINT`).

## Local trace dashboard (Jaeger)

A **Jaeger** all-in-one service provides a local dashboard for traces. It is
optional and behind the `jaeger` compose profile so it does not start by default:

```bash
# start the stack including Jaeger
docker compose --profile jaeger up -d

# open the Jaeger UI
open http://localhost:16686
```

When Jaeger is running, the Collector forwards traces to it by default
(`OTEL_FORWARD_ENDPOINT=http://jaeger:4318`).

## Enabling application traces

To see traces in Jaeger:

1. Start the stack with the `jaeger` profile (above).
2. Edit `.env`:
   ```dotenv
   OTEL_TRACES_ENABLED=true
   ```
3. Restart the stack and make a few HTTP requests (e.g. browse the dashboard or
   call the API).
4. Open `http://localhost:16686`, select the `argus-sbomguard` service and find
   your traces.

FastAPI request handling (in the web/app process), Celery task execution
(run by the worker) and outbound `httpx` calls (e.g. Slack notifications)
are instrumented automatically, so each HTTP request, background task and
notification produces a distributed trace. Task failures are recorded on the
task span, and the calls a task makes become children of its span, so you can
follow an SBOM scan or an alert delivery end to end. The worker initializes
tracing itself, so it does not need to go through the web process.

## Using another OTLP backend (e.g. Logfire)

The Collector forwards to whatever `OTEL_FORWARD_ENDPOINT` points at. To use a
different backend (for example the Pydantic Logfire cloud):

```dotenv
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318/v1/traces
OTEL_FORWARD_ENDPOINT=http://<logfire-or-other-backend>:4318
OTEL_FORWARD_TLS_INSECURE=false
```

Logfire is OpenTelemetry-native, so traces flow through unchanged. Note that
the app always pushes to the Collector first — only the forwarding destination
changes.

!!! note "TLS to the forwarding backend"

    The Collector defaults to `OTEL_FORWARD_TLS_INSECURE=true` because the
    in-stack Jaeger speaks plaintext HTTP. When `OTEL_FORWARD_ENDPOINT` points
    at an external backend over HTTPS (e.g. Logfire), set
    `OTEL_FORWARD_TLS_INSECURE=false` so TLS certificate verification is kept.

## Scraping

Point your Prometheus (or any Prometheus-compatible scraper) at:

```
https://<your-domain>/metrics
```

This endpoint is **unauthenticated** by design so the scraper needs no
credentials. See [Reverse Proxy + WAF](proxy.md#health) for the implications on
publicly reachable deployments.

Host metric examples available from the Collector:

```
system_cpu_time
process_memory_usage_bytes
filesystem_utilization
system_network_io
```

## Error tracking (product-agnostic)

Unhandled exceptions never depend on a third-party error-tracking vendor.
Instead, Argus emits every unhandled HTTP exception as a **structured JSON log
line** that any log aggregator, SIEM or error tracker can consume. Because it
rides the standard `LOG_FORMAT=json` pipeline, no extra dependency, exporter or
vendor is involved.

Each event looks like:

```json
{
  "timestamp": "2026-08-18T09:30:00.123456+00:00",
  "level": "ERROR",
  "logger": "app",
  "message": "kaboom",
  "module": "api.v1.projects",
  "line": 42,
  "pid": 1,
  "thread": "MainThread",
  "event": "exception",
  "type": "RuntimeError",
  "traceback": "Traceback (most recent call last):\n  ...\nRuntimeError: kaboom",
  "trace_id": "19af8d0c1b3a4e5f6a7b8c9d0e1f2a3b",
  "span_id": "1234567890abcdef",
  "request_method": "GET",
  "request_path": "/api/v1/projects",
  "request_query": "page=2",
  "request_client": "10.0.0.5"
}
```

- `event=exception` identifies the line as an error event.
- `type`, `message` and `traceback` describe the exception; `message` is the
  exception text.
- `trace_id` and `span_id` (hex, present when application traces are enabled)
  let you jump from the error event to the matching span in Jaeger or any
  OpenTelemetry backend — even though error events and traces use separate
  pipelines, they stay joinable.
- `request_*` fields carry the request context (method, path, query string and
  the immediate peer address uvicorn observed — behind the reverse proxy that
  is the Caddy/WAF hop, not the end client) so you can correlate the error
  with the affected endpoint and request.

The handler is registered for `Exception`, so it is wired into Starlette's
outermost `ServerErrorMiddleware`: it catches errors raised by the middleware
stack as well as by route handlers. The client only ever receives a generic
`Internal Server Error` 500 response — internals are never leaked.

## Configuration reference

| Setting | Default | Description |
|---------|---------|-------------|
| `OTEL_TRACES_ENABLED` | `false` | Enable application trace export. |
| `OTEL_SERVICE_NAME` | `argus-sbomguard` | Service name in the OTel resource. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4318/v1/traces` | Where the app pushes traces (the Collector). |
| `OTEL_FORWARD_ENDPOINT` | `http://jaeger:4318` | Where the Collector forwards traces. |
| `OTEL_FORWARD_TLS_INSECURE` | `true` | Skip TLS verification when forwarding; set `false` for external HTTPS backends. |
| `COMPOSE_PROFILES` | *(empty)* | Set to `jaeger` to run the local trace dashboard. |
