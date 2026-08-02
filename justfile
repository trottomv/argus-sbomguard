set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := false

# read version from pyproject.toml
_version := `grep '^version = ' app/pyproject.toml | sed 's/.*= "\(.*\)"/\1/'`

# show available recipes
help:
    @just --list

# ---- Build & Run ----

# start all services
up:
    docker compose up -d --build

# stop all services
down:
    docker compose down

# restart all services
restart:
    docker compose restart

# ---- Logs ----

# tail app logs
logs:
    docker compose logs -f app

# tail worker logs
logs-worker:
    docker compose logs -f worker

# ---- Testing ----

# run tests
test:
    docker compose exec app pytest -v

# run tests with coverage
test-cov:
    docker compose exec app pytest -v --cov=. --cov-report=term-missing

# run tests in watch mode
test-watch:
    docker compose exec app ptw -- -v

# ---- Lint & Format ----

# check linting
lint:
    docker compose exec app ruff check .

# fix linting issues
lint-fix:
    docker compose exec app ruff check --fix .

# format code
format:
    docker compose exec app ruff format .

# check formatting
format-check:
    docker compose exec app ruff format --check

# compile requirements with hashes (requires pip-tools on host: pip install pip-tools)
compile-requirements:
    @command -v pip-compile >/dev/null 2>&1 || { echo "pip-tools required. Install with: pip install pip-tools"; exit 1; }
    pip-compile --generate-hashes --no-header --resolver=backtracking --upgrade --allow-unsafe -o app/requirements/remote.txt app/pyproject.toml
    pip-compile --generate-hashes --no-header --resolver=backtracking --upgrade --extra dev --allow-unsafe -o app/requirements/dev.txt app/pyproject.toml

# ---- Security ----

# run bandit SAST
bandit:
    docker compose exec app bandit -c pyproject.toml -r .

# audit dependencies for known vulnerabilities
audit:
    docker compose exec app pip-audit --require-hashes --disable-pip -r requirements/remote.txt

# ---- Git ----

# run all pre-commit checks
pre-commit:
    pre-commit run --all-files

# ---- Database ----

# run pending migrations
db-upgrade:
    docker compose exec app alembic upgrade head

# create a new migration
db-make msg:
    docker compose exec app alembic revision --autogenerate -m "{{msg}}"

# show migration history
db-history:
    docker compose exec app alembic history

# ---- Shell ----

# open a shell in the app container
shell:
    docker compose exec app sh

# open a psql session
shell-db:
    docker compose exec postgres psql -U argus

# ---- Images & Proto ----

# scan all container images with syft
scan-all:
    @bash scripts/scan-all.sh

# regenerate gRPC protobuf stubs
proto:
    docker compose run --rm --no-deps --entrypoint python app -m grpc_tools.protoc -Iprotos --python_out=/app/protos/generated --grpc_python_out=/app/protos/generated protos/sbom.proto

# ---- Frontend ----

# build Tailwind CSS
css:
    cd app && bun install --frozen-lockfile && bun run build:css

# ---- Docs ----

# install docs dependencies into a local venv
docs-deps:
    test -d .docs-venv || python3 -m venv .docs-venv
    .docs-venv/bin/pip install -q "mike~=2.2" "mkdocs-material~=9.6" "mkdocstrings[python]~=0.29"

_docs-venv-bin := ".docs-venv/bin"

# serve docs locally on :8001
docs-serve: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mkdocs serve -a localhost:8001

# build docs static site (output: site/)
docs-build: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mkdocs build

# deploy a versioned docs release (reads version from pyproject.toml)
docs-release: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mike deploy --push --update-aliases {{_version}} latest
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mike set-default --push latest

# set default docs version to latest
docs-default: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mike set-default --push latest

# list published docs versions
docs-list: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mike list

# ---- Utils ----

# remove build artifacts and caches
clean:
    rm -rf app/__pycache__ app/**/__pycache__ app/.pytest_cache .ruff_cache site .docs-venv
