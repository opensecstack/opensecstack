.PHONY: help run build test test-unit test-integration test-content test-sandbox lint fmt migrate-up migrate-status migrate-down docker-build docker-compose-up docker-compose-down health proto clean

LDFLAGS := -X github.com/opensecstack/cyberpath/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev) \
           -X github.com/opensecstack/cyberpath/internal/version.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown) \
           -X github.com/opensecstack/cyberpath/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

DB_URL ?= postgres://cyberpath:cyberpath_dev@localhost:5439/cyberpath?sslmode=disable

## help: show available targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'

## run: start CyberPath locally against Postgres on :5439
run:
	CYBERPATH_DB_URL="$(DB_URL)" \
	go run ./cmd/server

## build: compile cyberpath-server + cyberpath-cli binaries
build:
	go build -ldflags="$(LDFLAGS)" -o bin/cyberpath-server ./cmd/server
	go build -ldflags="$(LDFLAGS)" -o bin/cyberpath-cli ./cmd/cyberpath-cli

## test-unit: run unit tests with race detector
test-unit:
	go test -race -count=1 ./...

## test: alias for test-unit
test: test-unit

## test-integration: run integration tests against live Postgres (requires -p 1)
test-integration:
	go test -tags integration -p 1 -count=1 ./...

## test-content: validate track.yaml + bilingual lesson coverage (TODO v1.0.0)
test-content:
	@echo "TODO(v1.0.0): cyberpath-cli content lint content/"

## test-sandbox: Wasm sandbox isolation tests (v1.0.0+)
test-sandbox:
	@echo "TODO(v1.0.0): cd rust && cargo test --package lab-runtime"

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## fmt: run gofmt + goimports on all Go files
fmt:
	gofmt -w -s .

## migrate-up: apply SQL migrations
migrate-up:
	psql "$(DB_URL)" -f internal/db/migrations/0001_initial.sql

## migrate-status: show applied migration files (placeholder until migration tool is wired)
migrate-status:
	@echo "Migrations on disk:" && ls internal/db/migrations/

## migrate-down: drop the public schema (DEV ONLY)
migrate-down:
	psql "$(DB_URL)" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

## docker-build: build the cyberpath-server container image
docker-build:
	docker build -t opensecstack/cyberpath:dev .

## docker-compose-up: start CyberPath + Postgres + Prometheus
docker-compose-up:
	docker compose up --build -d
	@echo "CyberPath: http://localhost:8086/healthz"

## docker-compose-down: stop all containers
docker-compose-down:
	docker compose down -v

## health: curl the health endpoint
health:
	curl -fsS http://localhost:8086/healthz || true

## proto: regenerate Go stubs (placeholder for v1.0.0+)
proto:
	@echo "TODO(v1.0.0+): protoc generation when proto/ is added"

## clean: remove build artefacts
clean:
	rm -rf bin/ dist/
