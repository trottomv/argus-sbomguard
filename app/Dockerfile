# syntax=docker/dockerfile:1

ARG BUN_VERSION=1
ARG PYTHON_VERSION=3.15

FROM dhi.io/bun:${BUN_VERSION}-alpine-dev@sha256:da31284d76f059bc8d29ba93ba0098e46de8e97f1485aa07a5503d0dda958017 AS css-builder

WORKDIR /build
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY static/ static/
COPY templates/ templates/
RUN bun run build:css


FROM dhi.io/grype:0-alpine@sha256:bda286d1951974e9373cbcb0745a098451ff055adbbb4ffea78d09ba041e583d AS grype


FROM dhi.io/python:${PYTHON_VERSION}-alpine-dev@sha256:0bb115e0b8c9d3e6856915aa45eb3108245dcc15c3b103e7b19ee703278376f1 AS base

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
