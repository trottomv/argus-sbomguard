# Supply Chain & Build Provenance

Every release image pushed to GHCR carries build provenance: the repository,
the exact commit it was built from, the build timestamp, and the deployment
environment. Signatures and provenance attestations are produced with
Sigstore (cosign) and Docker Buildx, so consumers can verify authenticity
without trusting the registry.

## What gets recorded

When the [build workflow](https://github.com/trottomv/argus-sbomguard/blob/main/.github/workflows/build.yml)
runs on a `v*` tag, the image is built with:

| Field | Source | OCI label | Runtime |
|-------|--------|-----------|---------|
| Version | `app/VERSION.md` (single source of truth) | `org.opencontainers.image.version` | `version` |
| Git commit | `github.sha` | `org.opencontainers.image.revision` | `git_sha` |
| Build date | CI timestamp (UTC) | `org.opencontainers.image.created` | `build_date` |
| Source repo | `github.repository` | `org.opencontainers.image.source` | `source_url` |
| Build environment | CI (`ci`) | — | `build_env` |
| Deployment environment | `APP_ENV` setting | — | `environment` |

The first five are baked into the image at build time via
[`app/Dockerfile`](https://github.com/trottomv/argus-sbomguard/blob/main/app/Dockerfile)
(`BUILD_GIT_SHA`, `BUILD_DATE`, `BUILD_SOURCE_URL`, `BUILD_ENV`); the
deployment environment is reported from the `APP_ENV` runtime setting. In local
(non-CI) builds the baked fields fall back to `unknown`.

## Provenance at runtime

The running application exposes the build provenance on two public endpoints:

```bash
curl -s http://localhost:8000/version
```

```json
{
  "service": "argus-sbomguard",
  "version": "0.0.7-beta",
  "git_sha": "1edf17104c2b1a5f7d26a1f19e6cf2d96e2e0aa4",
  "build_date": "2026-08-22T09:15:00Z",
  "source_url": "https://github.com/trottomv/argus-sbomguard",
  "build_env": "ci",
  "environment": "production"
}
```

The same fields (plus `status`) are returned by `/healthz`. The UI sidebar
shows the version number; the full provenance is available on `/version`.

## Image attestations

`docker/build-push-action` is configured with `provenance: true` and
`sbom: true`, so every push attaches two attestations to the image index:

- **SLSA provenance** (`https://slsa.dev/provenance/v1`) — records the build
  machine, the build inputs and the OCI configuration used.
- **SBOM** (`https://spdx.dev/Document`) — the software bill of materials of
  the image contents.

## Signing & verification

Release images are signed with Sigstore **keyless** signing (OIDC identity of
the GitHub Actions workflow), and the signature is stored in the Rekor
transparency log. The build workflow itself verifies the signature before it
finishes.

Inspect the signature of a released image:

```bash
cosign verify \
  ghcr.io/trottomv/argus-sbomguard:<tag> \
  --certificate-identity-regexp "https://github.com/trottomv/argus-sbomguard/.github/workflows/build.yml@refs/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Verify the SBOM and SLSA provenance attestations:

```bash
cosign verify-attestation \
  ghcr.io/trottomv/argus-sbomguard:<tag> \
  --type https://spdx.dev/Document \
  --certificate-identity-regexp "https://github.com/trottomv/argus-sbomguard/.github/workflows/build.yml@refs/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation \
  ghcr.io/trottomv/argus-sbomguard:<tag> \
  --type https://slsa.dev/provenance/v1 \
  --certificate-identity-regexp "https://github.com/trottomv/argus-sbomguard/.github/workflows/build.yml@refs/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Or use the shortcut:

```bash
just verify-image ghcr.io/trottomv/argus-sbomguard:0.0.7-beta
```

`cosign` must be installed locally (e.g. `brew install cosign` or the
[released binaries](https://github.com/sigstore/cosign/releases)).
