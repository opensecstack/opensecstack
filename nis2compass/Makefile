.PHONY: help dev dev-down install fmt lint test test-cov test-fast migrate migrate-down db-reset security clean

# Default target
help:
	@echo "NIS2 Compass - available targets:"
	@echo ""
	@echo "  dev          Start full stack with Docker Compose (dev profile)"
	@echo "  dev-down     Stop dev stack"
	@echo "  install      Install runtime and dev dependencies"
	@echo ""
	@echo "  fmt          Format code with black and isort"
	@echo "  lint         Run flake8, black --check, isort --check, mypy"
	@echo "  test         Run test suite with verbose output"
	@echo "  test-cov     Run tests with HTML coverage report"
	@echo "  test-fast    Run tests, stop on first failure"
	@echo ""
	@echo "  migrate      Apply all pending Alembic migrations"
	@echo "  migrate-down Roll back one Alembic migration"
	@echo "  db-reset     Downgrade to base then upgrade to head"
	@echo ""
	@echo "  security     Run bandit SAST and pip-audit CVE check"
	@echo "  clean        Remove build/cache artefacts"

# ── Docker ────────────────────────────────────────────────────────────────────

dev:
	docker compose -f docker-compose.dev.yml up --build

dev-down:
	docker compose -f docker-compose.dev.yml down

# ── Python dependencies ────────────────────────────────────────────────────────

install:
	pip install -r requirements.txt -r requirements-dev.txt

# ── Code quality ───────────────────────────────────────────────────────────────

fmt:
	black app/ tests/
	isort app/ tests/

lint:
	flake8 app/
	black --check app/
	isort --check-only app/
	mypy app/ --ignore-missing-imports

# ── Tests ──────────────────────────────────────────────────────────────────────

test:
	pytest tests/ -v

test-cov:
	pytest tests/ -v --cov=app --cov-report=term-missing --cov-report=html

test-fast:
	pytest tests/ -x -q

# ── Database migrations ────────────────────────────────────────────────────────

migrate:
	alembic upgrade head

migrate-down:
	alembic downgrade -1

db-reset:
	alembic downgrade base
	alembic upgrade head

# ── Security ───────────────────────────────────────────────────────────────────

security:
	bandit -r app/
	pip-audit -r requirements.txt

# ── Cleanup ────────────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .mypy_cache  -exec rm -rf {} +
	find . -type d -name htmlcov      -exec rm -rf {} +
	find . -name .coverage            -delete
