# Versioning & Deprecation Policy

Argus SBOM Guard's REST API is versioned and its public contract is frozen for
the current major version. This page describes how versions are chosen, what is
guaranteed to stay stable, and how endpoints are deprecated and removed.

## Versioning

The API uses a **URI path prefix** for the major version:

```
/api/v1/projects
/api/v1/sboms/...
```

- The **major version** lives in the path (`v1`). A breaking change ships as a
  new major version (`/api/v2/...`), never as a silent change to `v1`.
- The **application version** (`app/VERSION.md`, reported in `info.version` of
  the OpenAPI schema and in `GET /healthz`) follows [SemVer](https://semver.org/).
  The API major version is independent from the application minor/patch — `v1`
  is stable across application releases.

## Stability Guarantees

For the current major version (`v1`):

- Existing endpoints, their HTTP methods, and their response shapes **will not
  change in a breaking way**.
- New functionality is **additive only**: new endpoints, new optional request
  fields, and new optional response fields may be introduced. Response objects
  never have fields removed or re-typed.
- `GET` endpoints remain side-effect free.

This is what "frozen contract" means for `/api/v1`.

## Deprecation Policy

Before an endpoint is removed, it goes through a **deprecation period**. A
deprecated endpoint:

1. Is marked `deprecated: true` in the OpenAPI schema.
2. Emits a `Deprecation` response header (RFC 8594) with the date after which
   the endpoint will be removed.
3. Continues to work unchanged until the end of the deprecation period.

Removal happens **only in a new major version**. Within the current major
version, deprecated endpoints are kept functional and backward compatible.

| Phase | Signal | Minimum duration |
|-------|--------|------------------|
| Active | — | — |
| Deprecated | `deprecated: true` + `Deprecation` header | ≥ one minor application release |
| Removed | 410/404 in the next major version | — |

## OpenAPI Schema

The machine-readable contract for the current version is published at:

```
GET /api/openapi.json
```

Browse it at `/api/docs` (ReDoc). A static copy is committed at
[`openapi.json`](openapi.json) for offline browsing. The schema's
`info.version` reflects the application version that generated it. The canonical
schema is always generated from the running application — regenerate the
committed copy with `scripts/generate_openapi.sh` whenever the API changes.
