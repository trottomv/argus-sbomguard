# --------------------
# justfile
# --------------------
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := false

help:
    @just --list

# start everything
up:
    docker compose up -d --build

# stop everything
down:
    docker compose down

# restart
restart:
    docker compose restart

# logs
logs:
    docker compose logs -f app

logs-worker:
    docker compose logs -f worker

# tests
test:
    docker compose exec app pytest -v

test-cov:
    docker compose exec app pytest -v --cov=. --cov-report=term-missing

test-watch:
    docker compose exec app ptw -- -v

# lint
lint:
    docker compose exec app ruff check .

lint-fix:
    docker compose exec app ruff check --fix .

format:
    docker compose exec app ruff format .

format-check:
    docker compose exec app ruff format --check

# security
bandit:
    docker compose exec app bandit -c pyproject.toml -r .

audit:
    docker compose exec app pip-audit --strict -r requirements.txt

# pre-commit
pre-commit:
    pre-commit run --all-files

# database
db-upgrade:
    docker compose exec app alembic upgrade head

db-make msg:
    docker compose exec app alembic revision --autogenerate -m "{{msg}}"

db-history:
    docker compose exec app alembic history

# shell
shell:
    docker compose exec app sh

shell-db:
    docker compose exec postgres psql -U argus

# scan all images with syft
scan-all:
    @bash scripts/scan-all.sh

# regenerate protobuf stubs
proto:
    docker compose run --rm --no-deps --entrypoint python app -m grpc_tools.protoc -Iprotos --python_out=/app/protos/generated --grpc_python_out=/app/protos/generated protos/sbom.proto

# build tailwind CSS
css:
    cd app && npm ci && npm run build:css

# clean
clean:
    rm -rf app/__pycache__ app/**/__pycache__ app/.pytest_cache .ruff_cache
