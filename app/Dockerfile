FROM dhi.io/node:24-alpine3.23-dev AS css-builder

WORKDIR /build
COPY package.json package-lock.json* ./
RUN npm ci
COPY static/ static/
COPY templates/ templates/
RUN npm run build:css


FROM alpine:3.21 AS grype-downloader
ARG GRYPE_VERSION=v0.116.0
RUN apk add --no-cache curl tar
RUN curl -fsSL "https://github.com/anchore/grype/releases/download/${GRYPE_VERSION}/grype_${GRYPE_VERSION#v}_linux_amd64.tar.gz" \
    | tar xz -C /usr/local/bin grype


FROM dhi.io/python:3.13-alpine-dev AS base

WORKDIR /app

RUN apk add --no-cache build-base linux-headers

COPY requirements.txt alembic.ini ./
COPY migrations/ migrations/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/
RUN python -m grpc_tools.protoc -Iprotos --python_out=/app --grpc_python_out=/app protos/sbom.proto

COPY --from=css-builder /build/static/css/dist.css /app/static/css/dist.css
COPY --from=grype-downloader /usr/local/bin/grype /usr/local/bin/grype

RUN chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]


FROM base AS test

RUN pip install --no-cache-dir \
    pytest>=8.3.0 \
    pytest-asyncio>=0.25.0 \
    pytest-cov>=6.0.0 \
    pytest-httpx>=0.35.0 \
    aiosqlite>=0.20.0
CMD ["pytest", "-v", "--cov=.", "--cov-report=term-missing"]
