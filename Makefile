.PHONY: dev up test test-coverage build lint fmt migrate clean docs audit scan security

# Start full ecosystem stack with hot reload
dev:
	docker compose -f deploy/docker-compose.dev.yml up --build

# Start production-like stack
up:
	docker compose -f deploy/docker-compose.yml up -d

# Run all tests across all platforms
test:
	cd apiguard && $(MAKE) test
	cd nis2compass && pytest tests/ -v

# Run tests with coverage reports across all platforms
test-coverage:
	cd apiguard && $(MAKE) test-coverage
	cd nis2compass && pytest tests/ -v --cov=app --cov-report=html --cov-report=term-missing --cov-fail-under=70

# Build all platform Docker images
build:
	docker compose -f deploy/docker-compose.yml build

# Run linters across all platforms
lint:
	cd apiguard && $(MAKE) lint
	cd nis2compass && flake8 app/ --max-line-length=120 && black --check app/ && isort --check-only app/

# Format all source files across all platforms
fmt:
	cd apiguard && $(MAKE) fmt
	cd nis2compass && black app/ && isort app/

# Run database migrations for all platforms
migrate:
	cd apiguard && $(MAKE) migrate
	cd nis2compass && alembic upgrade head

# Run dependency CVE audits across all platforms
audit:
	@echo "==> Auditing Go dependencies (APIGuard)..."
	cd apiguard && go list -json -m all | nancy sleuth
	@echo "==> Auditing Rust dependencies (APIGuard)..."
	cd apiguard/rust && cargo audit
	@echo "==> Auditing Python dependencies (NIS2 Compass)..."
	cd nis2compass && pip-audit -r requirements.txt

# Run SAST scanners across all platforms
scan:
	@echo "==> Running gosec (APIGuard Go)..."
	cd apiguard && gosec ./...
	@echo "==> Running cargo clippy (APIGuard Rust)..."
	cd apiguard/rust && cargo clippy --workspace -- -D warnings
	@echo "==> Running bandit (NIS2 Compass Python)..."
	cd nis2compass && bandit -r app/

# Run all security checks (audit + scan)
security: audit scan
	@echo "==> All security checks passed."

# Remove all containers, volumes, and build artifacts
clean:
	docker compose -f deploy/docker-compose.yml down -v
	docker compose -f deploy/docker-compose.dev.yml down -v
	cd apiguard && $(MAKE) clean

# Start documentation site
docs:
	cd apiguard && $(MAKE) docs
