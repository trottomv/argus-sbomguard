# syntax=docker/dockerfile:1

ARG BUN_VERSION=1
ARG PYTHON_VERSION=3.13

FROM dhi.io/bun:${BUN_VERSION}-alpine-dev@sha256:35f2f06160715cdb3855166916b663f87642b816fa121632708f082e866db96e AS css-builder

WORKDIR /build
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY static/ static/
COPY templates/ templates/
RUN bun run build:css


FROM dhi.io/grype:0-alpine@sha256:0b6aaae34ba62a74ca396fbd39105aae8c76663b807b5e697f31de2efdc2c5c0 AS grype


FROM dhi.io/python:${PYTHON_VERSION}-alpine-dev@sha256:d45bbc7271a4b8553a0591093d8fc19ea320a55cb4dae5412c450d5b36f20822 AS base

ARG APP_USER=appuser
ARG UV_VERSION=~=0.13.0
ARG PIP_VERSION=~=26.2.0
# Build provenance (repository, commit, environment) baked into the image.
# CI (build.yml) passes these as build args; local builds fall back to
# "unknown". OCI labels (org.opencontainers.image.*) are managed by CI via
# docker/metadata-action, so only the runtime-facing env vars are set here.
ARG BUILD_GIT_SHA=unknown
ARG BUILD_DATE=unknown
ARG BUILD_SOURCE_URL=unknown
ARG BUILD_ENV=unknown
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/app/protos/generated \
    APP_USER=${APP_USER} \
    BUILD_GIT_SHA=${BUILD_GIT_SHA} \
    BUILD_DATE=${BUILD_DATE} \
    BUILD_SOURCE_URL=${BUILD_SOURCE_URL} \
    BUILD_ENV=${BUILD_ENV}
WORKDIR /app

RUN apk add --no-cache build-base \
    && addgroup -S ${APP_USER} \
    && adduser -S ${APP_USER} -G ${APP_USER} \
    && python3 -m pip install --no-cache-dir "pip${PIP_VERSION}" \
    && python3 -m pip install --no-cache-dir "uv${UV_VERSION}"


FROM base AS build

COPY requirements/remote.txt requirements/
RUN uv pip install --system --require-hashes --no-cache -r requirements/remote.txt

COPY alembic.ini ./
COPY migrations/ migrations/
COPY . /app/
RUN mkdir -p /app/protos/generated \
    && python3 -m grpc_tools.protoc -Iprotos --python_out=/app/protos/generated --grpc_python_out=/app/protos/generated protos/sbom.proto

COPY --from=css-builder /build/static/css/dist.css /app/static/css/dist.css
COPY --from=grype /usr/bin/grype /usr/local/bin/grype

RUN mkdir -p /home/${APP_USER}/.cache/grype \
    && chown -R ${APP_USER}:${APP_USER} /app /home/${APP_USER}/.cache

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.py"]


FROM build AS remote-debug

USER ${APP_USER}

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]


FROM remote-debug AS remote

USER root
RUN rm -f /bin/sh /bin/bash
USER ${APP_USER}

FROM build AS development

RUN uv pip install --system --require-hashes --no-cache -r requirements/dev.txt

USER ${APP_USER}

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


FROM build AS test

RUN uv pip install --system --require-hashes --no-cache -r requirements/dev.txt

USER ${APP_USER}

CMD ["pytest", "-v", "--cov=.", "--cov-report=term-missing"]
