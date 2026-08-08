# CI/CD Integration

Wire Argus SBOM Guard into your CI/CD pipeline so every build automatically
publishes the SBOM of the artifact you just produced. Argus then parses it,
stores the dependencies, and kicks off a Grype vulnerability scan in the
background — no extra steps needed.

## How It Works

1. **Build the artifact** — a container image, a binary, or the source tree.
2. **Generate an SBOM** from that artifact with [Syft](https://github.com/anchore/syft).
3. **Upload it to Argus** with a single `curl` call against the
   [`POST /api/v1/sboms/upload`](../api/reference.md#sboms) endpoint.
4. **Attach it to the pipeline** as a build artifact for later download and
   audit.

Argus deduplicates SBOMs by SHA-256, so uploading the same artifact twice is
harmless — you still get one record per unique SBOM.

## Prerequisites

- An **Argus instance reachable from your CI runners** — the base URL, e.g.
  `https://argus.example.com`.
- A **project UUID** from **Projects** → *your project*.
- An **API key** generated under **Settings** → **Generate Key** (see
  [API Authentication](../setup.md#api-authentication)).

## Configuration

Store these as CI/CD variables or repository secrets — **never** in plaintext
YAML:

| Variable | Example | Purpose |
|----------|---------|---------|
| `ARGUS_URL` | `https://argus.example.com` | Base URL of your Argus instance |
| `ARGUS_PROJECT_ID` | `00000000-0000-0000-0000-000000000001` | UUID of the target project |
| `ARGUS_API_KEY` | `argus_xxxxxxxxxxxx` | API key sent in the `X-API-Key` header |

The upload itself is a standard multipart request:

```bash
curl -f -X POST "$ARGUS_URL/api/v1/sboms/upload" \
  -H "X-API-Key: $ARGUS_API_KEY" \
  -F "project_id=$ARGUS_PROJECT_ID" \
  -F "version=1.2.3" \
  -F "service_name=my-app" \
  -F "file=@sbom.json"
```

| Field | Purpose |
|-------|---------|
| `file` | The generated SBOM, as CycloneDX JSON (primary) or SPDX JSON |
| `version` | Version of the artifact, e.g. the git tag or commit SHA |
| `service_name` | Name of the microservice/component this SBOM belongs to |

## GitHub Actions

=== "GitHub Actions"

    ```yaml
    name: build-and-upload-sbom

    on:
      push:
        branches: [main]
        tags: ['v*']
      workflow_dispatch:

    permissions:
      contents: read

    jobs:
      build-and-upload-sbom:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v7

          - name: Install Syft (pinned)
            run: |
              curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
                | sh -s -- -b /usr/local/bin v1.50.0

          - name: Build artifact
            run: |
              docker build -t my-app:${{ github.sha }} .

          - name: Generate SBOM (CycloneDX JSON)
            run: |
              syft scan my-app:${{ github.sha }} -o cyclonedx-json > sbom.json

          - name: Upload SBOM to Argus
            env:
              ARGUS_URL: ${{ secrets.ARGUS_URL }}
              ARGUS_API_KEY: ${{ secrets.ARGUS_API_KEY }}
              ARGUS_PROJECT_ID: ${{ secrets.ARGUS_PROJECT_ID }}
            run: |
              curl -f -X POST "$ARGUS_URL/api/v1/sboms/upload" \
                -H "X-API-Key: $ARGUS_API_KEY" \
                -F "project_id=$ARGUS_PROJECT_ID" \
                -F "version=${GITHUB_REF_NAME}" \
                -F "service_name=my-app" \
                -F "file=@sbom.json"

          - name: Attach SBOM to pipeline
            uses: actions/upload-artifact@v7
            with:
              name: sbom
              path: sbom.json
    ```

    - Add the three variables as **repository secrets**:
      **Settings → Secrets and variables → Actions**.
    - Use `anchore/sbom-action@v0` instead of installing Syft manually if you
      prefer a maintained action — it supports the same `path`/`image` inputs
      and `format: cyclonedx-json`.
    - Replace `my-app` with your service name; for a multi-service repo, run
      one job per service and use its name as `service_name`.
    - `version=${GITHUB_REF_NAME}` is the tag on a tag push (e.g. `v1.2.3`) but
      `main` on a branch build. If you always want a real version, use a short
      SHA instead:
      `-F "version=$([ "$GITHUB_REF_TYPE" = tag ] && echo "$GITHUB_REF_NAME" || echo "${GITHUB_SHA::7}")"`.

## GitLab CI

=== "GitLab CI"

    ```yaml
    stages:
      - build
      - sbom

    variables:
      ARGUS_URL: https://argus.example.com
      ARGUS_PROJECT_ID: 00000000-0000-0000-0000-000000000001

    build:
      stage: build
      image: docker:27
      services:
        - docker:27-dind
      script:
        - docker build -t my-app:$CI_COMMIT_SHA .
        - docker save my-app:$CI_COMMIT_SHA -o image.tar
      artifacts:
        paths:
          - image.tar
        expire_in: 1 hour

    upload-sbom:
      stage: sbom
      image: docker:27
      services:
        - docker:27-dind
      needs:
        - build
      script:
        - apk add --no-cache curl
        - curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
            | sh -s -- -b /usr/local/bin v1.50.0
        - docker load -i image.tar
        - syft scan my-app:$CI_COMMIT_SHA -o cyclonedx-json > sbom.json
        - curl -f -X POST "$ARGUS_URL/api/v1/sboms/upload" \
            -H "X-API-Key: $ARGUS_API_KEY" \
            -F "project_id=$ARGUS_PROJECT_ID" \
            -F "version=$CI_COMMIT_TAG" \
            -F "service_name=my-app" \
            -F "file=@sbom.json"
      artifacts:
        paths:
          - sbom.json
        expire_in: 1 week
    ```

    - Define `ARGUS_API_KEY` as a **masked** CI/CD variable
      (**Settings → CI/CD → Variables**) so it never leaks into job logs.
    - `ARGUS_URL` and `ARGUS_PROJECT_ID` can be plain variables; they are not
      secret.
    - `version` is set to `$CI_COMMIT_TAG` (empty on non-tag pipelines — you can
      fall back to `$CI_COMMIT_SHORT_SHA` if you always want a version):
      `-F "version=${CI_COMMIT_TAG:-$CI_COMMIT_SHORT_SHA}"`.

## Best Practices

- **Pin the Syft version** (`v1.50.0` in the examples) so the generated SBOM is
  reproducible. Check for newer releases at
  [anchore/syft releases](https://github.com/anchore/syft/releases).
- **Use CycloneDX JSON** — it is Argus's primary SBOM format (SPDX JSON is also
  supported).
- **Generate the SBOM from the built artifact**, not from the source tree
  alone: the image or package that actually ships is what should be scanned.
- **Upload to Argus *and* keep the SBOM as a pipeline artifact** — the artifact
  preserves the exact file for audits and for
  [diffing versions](sboms.md#diffing-two-sboms) later.
- **Treat the API key as a secret** — masked variable (GitLab) or repository
  secret (GitHub), scoped to the job that needs it.
- **Only push on the branches/tags you care about** — the examples trigger on
  `main` and release tags; scanning every feature branch just consumes Grype
  worker capacity.
- **Let Argus do the vulnerability scanning** — once the SBOM is uploaded,
  Grype runs automatically and results appear on the
  [Vulnerabilities](vulnerabilities.md) page. No Grype step is needed in your CI.
