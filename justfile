# --------------------
# justfile
# --------------------
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := false

# read version from pyproject.toml
_version := `grep '^version = ' app/pyproject.toml | sed 's/.*= "\(.*\)"/\1/'`

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

# compile requirements with hashes (requires pip-tools on host: pip install pip-tools)
compile-requirements:
    @command -v pip-compile >/dev/null 2>&1 || { echo "pip-tools required. Install with: pip install pip-tools"; exit 1; }
    pip-compile --generate-hashes --no-header --resolver=backtracking --upgrade --allow-unsafe -o app/requirements/remote.txt app/pyproject.toml
    pip-compile --generate-hashes --no-header --resolver=backtracking --upgrade --extra dev --allow-unsafe -o app/requirements/dev.txt app/pyproject.toml

# security
bandit:
    docker compose exec app bandit -c pyproject.toml -r .

audit:
    docker compose exec app pip-audit --require-hashes --disable-pip -r requirements/remote.txt

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
    cd app && bun install --frozen-lockfile && bun run build:css

# install docs dependencies into a local venv
docs-deps:
    test -d .docs-venv || python3 -m venv .docs-venv
    .docs-venv/bin/pip install -q "mike~=2.2" "mkdocs-material~=9.6" "mkdocstrings[python]~=0.29"

_docs-venv-bin := ".docs-venv/bin"

# serve docs locally
docs-serve: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mkdocs serve -a localhost:8001

# build docs static site (in site/)
docs-build: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mkdocs build

# deploy a versioned docs release (reads version from pyproject.toml)
docs-release: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mike deploy --push --update-aliases {{_version}} latest
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mike set-default --push latest

# set default docs version (usually latest)
docs-default: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mike set-default --push latest

# list published docs versions
docs-list: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mike list

# clean
clean:
    rm -rf app/__pycache__ app/**/__pycache__ app/.pytest_cache .ruff_cache site .docs-venv
