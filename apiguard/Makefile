.PHONY: dev test test-coverage test-fp bench build lint fmt migrate migrate-down db-reset seed logs scan-example clean docs release

# Start full local stack with hot reload
dev:
	docker compose -f docker-compose.dev.yml up --build

# Run all tests: Rust + Go + integration + false positive
test:
	cargo test --workspace
	go test ./...
	cargo test --test integration
	go test ./tests/fp/...

# Run tests with coverage report
test-coverage:
	cargo tarpaulin --workspace --out Html
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run false positive tests only against clean API target
test-fp:
	go test ./tests/fp/... -v

# Run performance benchmarks
bench:
	cargo bench
	go test -bench=. -benchmem ./...

# Build production Docker images
build:
	docker compose build

# Run linters
lint:
	golangci-lint run ./...
	cargo clippy --workspace -- -D warnings
	cd web && npx eslint src/

# Format all source files
fmt:
	gofmt -w .
	cargo fmt --all
	cd web && npx prettier --write src/

# Run pending PostgreSQL migrations
migrate:
	go run ./cmd/migrate up

# Roll back the last applied migration
migrate-down:
	docker compose -f docker-compose.dev.yml run --rm migrate \
		-path=/migrations \
		-database=postgres://apiguard:devpassword@postgres:5432/apiguard?sslmode=disable \
		down 1

# Drop and recreate the dev database, then re-run all migrations
db-reset:
	docker compose -f docker-compose.dev.yml exec postgres \
		psql -U apiguard -c "DROP DATABASE IF EXISTS apiguard;" postgres
	docker compose -f docker-compose.dev.yml exec postgres \
		psql -U apiguard -c "CREATE DATABASE apiguard;" postgres
	$(MAKE) migrate

# Run the seed script to populate dev data
seed:
	go run ./cmd/seed

# Tail live API logs from the dev stack
logs:
	docker compose -f docker-compose.dev.yml logs -f apiguard-api

# Run APIGuard against VAmPI example target
scan-example:
	docker compose -f docker-compose.test.yml up -d vampi
	sleep 5
	go run ./cmd/apiguard scan --spec ./tests/integration/vampi-openapi.yaml --target http://localhost:5001 --format html --output ./reports/example-report.html

# Remove all containers, volumes, and build artifacts
clean:
	docker compose -f docker-compose.yml down -v
	docker compose -f docker-compose.dev.yml down -v
	docker compose -f docker-compose.test.yml down -v
	cargo clean
	rm -rf reports/*.html reports/*.pdf reports/*.json

# Start local documentation site
docs:
	cd docs && mkdocs serve -a 0.0.0.0:4000

# Tag, build, and push release images
release:
	@test -n "$(TAG)" || (echo "Usage: make release TAG=v0.1.0" && exit 1)
	git tag -a $(TAG) -m "Release $(TAG)"
	docker compose build
	docker compose push
