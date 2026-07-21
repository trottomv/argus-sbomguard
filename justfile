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
    docker compose exec app bash

shell-db:
    docker compose exec postgres psql -U argus

# clean
clean:
    rm -rf app/__pycache__ app/**/__pycache__ app/.pytest_cache .ruff_cache
