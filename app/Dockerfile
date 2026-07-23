FROM dhi.io/node:24-alpine3.23-dev AS css-builder

WORKDIR /build
COPY package.json package-lock.json* ./
RUN npm ci
COPY static/ static/
COPY templates/ templates/
RUN npm run build:css


FROM dhi.io/grype:0-alpine AS grype


FROM dhi.io/python:3.13-alpine-dev AS base

WORKDIR /app

COPY requirements.txt alembic.ini ./
COPY migrations/ migrations/
RUN apk add --no-cache build-base \
    && pip install --no-cache-dir -r requirements.txt

COPY . /app/
RUN python -m grpc_tools.protoc -Iprotos --python_out=/app/protos/generated --grpc_python_out=/app/protos/generated protos/sbom.proto

COPY --from=css-builder /build/static/css/dist.css /app/static/css/dist.css
COPY --from=grype /usr/bin/grype /usr/local/bin/grype

RUN adduser -D appuser \
    && chown -R appuser:appuser /app \
    && chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app:/app/protos/generated
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

EXPOSE 8000
USER appuser
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]


FROM base AS test

USER root
RUN pip install --no-cache-dir \
    pytest>=8.3.0 \
    pytest-asyncio>=0.25.0 \
    pytest-cov>=6.0.0 \
    pytest-httpx>=0.35.0 \
    aiosqlite>=0.20.0
USER appuser
CMD ["pytest", "-v", "--cov=.", "--cov-report=term-missing"]
