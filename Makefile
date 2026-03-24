.PHONY: dev test build lint fmt clean docs

# Start full ecosystem stack with hot reload
dev:
	docker compose -f deploy/docker-compose.dev.yml up --build

# Start production-like stack
up:
	docker compose -f deploy/docker-compose.yml up -d

# Run all tests across all platforms
test:
	cd apiguard && $(MAKE) test

# Build all platform Docker images
build:
	docker compose -f deploy/docker-compose.yml build

# Run linters across all platforms
lint:
	cd apiguard && $(MAKE) lint

# Format all source files across all platforms
fmt:
	cd apiguard && $(MAKE) fmt

# Run database migrations for all platforms
migrate:
	cd apiguard && $(MAKE) migrate

# Remove all containers, volumes, and build artifacts
clean:
	docker compose -f deploy/docker-compose.yml down -v
	docker compose -f deploy/docker-compose.dev.yml down -v
	cd apiguard && $(MAKE) clean

# Start documentation site
docs:
	cd apiguard && $(MAKE) docs
