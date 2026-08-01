# syntax=docker/dockerfile:1

ARG BUN_VERSION=1
ARG PYTHON_VERSION=3.13

FROM dhi.io/bun:${BUN_VERSION}-alpine-dev AS css-builder

WORKDIR /build
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY static/ static/
COPY templates/ templates/
RUN bun run build:css


FROM dhi.io/grype:0-alpine AS grype


FROM dhi.io/python:${PYTHON_VERSION}-alpine-dev AS base

ARG APP_USER=appuser

WORKDIR /app

RUN apk add --no-cache build-base \
    && addgroup -S ${APP_USER} \
    && adduser -S ${APP_USER} -G ${APP_USER}

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/app/protos/generated \
    APP_USER=${APP_USER}


FROM base AS build

COPY requirements/remote.txt requirements/
RUN python3 -m pip install --no-cache-dir --require-hashes -r requirements/remote.txt

COPY alembic.ini ./
COPY migrations/ migrations/
COPY . /app/
RUN python3 -m grpc_tools.protoc -Iprotos --python_out=/app/protos/generated --grpc_python_out=/app/protos/generated protos/sbom.proto

COPY --from=css-builder /build/static/css/dist.css /app/static/css/dist.css
COPY --from=grype /usr/bin/grype /usr/local/bin/grype

RUN chown -R ${APP_USER}:${APP_USER} /app

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]


FROM build AS remote

USER ${APP_USER}

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]


FROM build AS development

RUN python3 -m pip install --no-cache-dir --require-hashes -r requirements/dev.txt

USER ${APP_USER}

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]


FROM build AS test

RUN python3 -m pip install --no-cache-dir --require-hashes -r requirements/dev.txt

USER ${APP_USER}

CMD ["pytest", "-v", "--cov=.", "--cov-report=term-missing"]
