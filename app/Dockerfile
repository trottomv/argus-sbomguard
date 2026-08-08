# syntax=docker/dockerfile:1

ARG BUN_VERSION=1
ARG PYTHON_VERSION=3.13

FROM dhi.io/bun:${BUN_VERSION}-alpine-dev@sha256:d364f4eb6d20f8e906bdb9d12726995f8335878f46e0c1c69c910df9d92df5d8 AS css-builder

WORKDIR /build
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY static/ static/
COPY templates/ templates/
RUN bun run build:css


FROM dhi.io/grype:0-alpine@sha256:d19bddcf5064184f5a833303dc68e2b1a65a2c712aabd52278f4748d385006e2 AS grype


FROM dhi.io/python:${PYTHON_VERSION}-alpine-dev@sha256:8c3820102033dff6a1e5de0fad001747c7b0979c372d6ffc1ac95dd0e03eed82 AS base

ARG APP_USER=appuser
ARG UV_VERSION=~=0.12.0
ARG PIP_VERSION=~=26.2.0
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/app/protos/generated \
    APP_USER=${APP_USER}
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

RUN chown -R ${APP_USER}:${APP_USER} /app

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.py"]


FROM build AS remote-debug

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]

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
