FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt alembic.ini ./
COPY alembic/ alembic/
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh app/ /app/

RUN chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]


FROM base AS test

COPY tests/ /app/tests/
RUN pip install --no-cache-dir \
    pytest>=8.3.0 \
    pytest-asyncio>=0.25.0 \
    pytest-cov>=6.0.0 \
    pytest-httpx>=0.35.0 \
    aiosqlite>=0.20.0
CMD ["pytest", "-v", "--cov=app", "--cov-report=term-missing"]
