set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := false

# read version from app/VERSION.md
_version := `cat app/VERSION.md`

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

# run tests via the standalone test stack (never in the dev app container)
test:
    COMPOSE_FILE=docker-compose.test.yml docker compose run --rm app pytest -v

# build the test image and run the full suite in a fresh standalone stack.
# The test image CMD already runs pytest with coverage (--cov=. --cov-report=term-missing),
# so coverage output is produced on every run; teardown removes the stack afterwards.
test-stack:
    COMPOSE_FILE=docker-compose.test.yml docker compose build app
    COMPOSE_FILE=docker-compose.test.yml docker compose run --rm app
    COMPOSE_FILE=docker-compose.test.yml docker compose down -v

# run tests writing coverage annotate output into cov_annotate/ (gitignored).
# cleanup happens inside the container because the files are root-owned there.
cov-annotate:
    COMPOSE_FILE=docker-compose.test.yml docker compose run --rm app sh -c "rm -rf /app/cov_annotate && pytest -q --cov=. --cov-report=annotate:cov_annotate"

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

# compile requirements with hashes, upgrading to latest within pyproject ranges
# (requires uv on host: pipx install uv)
UV_VERSION := env_var_or_default("UV_VERSION", "~=0.12.0")
compile-requirements:
    @command -v uv >/dev/null 2>&1 || { echo "uv {{UV_VERSION}} required. Install with: pipx install \"uv{{UV_VERSION}}\""; exit 1; }
    @echo "Compiling with uv $(uv --version | cut -d' ' -f2) (pinned specifier: {{UV_VERSION}})..."
    uv pip compile app/pyproject.toml --generate-hashes --upgrade --no-header -o app/requirements/remote.txt
    uv pip compile app/pyproject.toml --extra dev --generate-hashes --upgrade --no-header -o app/requirements/dev.txt

# list outdated dependencies (installed in the app container vs latest on PyPI)
outdated:
    docker compose exec app uv pip list --outdated

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

# ---- Backup & Restore ----

# create a compressed PostgreSQL backup in the backup container
# (pg_dump + gzip, retention-pruned; encrypted when BACKUP_ENCRYPTION_KEY is set)
db-backup:
    docker compose run --no-tty --rm --no-deps backup /usr/local/bin/backup.sh

# restore a PostgreSQL backup from the backup container; pass the file name
# relative to BACKUP_DIR and --reset to drop and recreate the database first
db-restore file args:
    docker compose run --no-tty --rm --no-deps backup /usr/local/bin/restore.sh /backups/{{file}} {{args}}

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

# propagate the version from app/VERSION.md to README, compose fallback,
# .env.example and docs. Edit app/VERSION.md first, then run.
bump-version:
    python3 scripts/bump_version.py

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

# regenerate the committed OpenAPI schema from a running instance
docs-openapi:
    @bash scripts/generate_openapi.sh

# list published docs versions
docs-list: docs-deps
    PATH="{{_docs-venv-bin}}:$PATH" {{_docs-venv-bin}}/mike list

# ---- Utils ----

# remove build artifacts and caches. Files under app/ are container-generated
# and root-owned, so they are cleaned inside the test container (runs as root).
clean:
    COMPOSE_FILE=docker-compose.test.yml docker compose run --rm app sh -c "find /app -name __pycache__ -type d -prune -exec rm -rf {} + && rm -rf /app/.pytest_cache /app/.ruff_cache /app/cov_annotate && find /app -name '*,cover' -delete"
    rm -rf site .docs-venv
