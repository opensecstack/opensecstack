.PHONY: build test test-integration test-e2e test-all bench release-notes lint fmt vet security run clean docker docker-dev

BINARY := bin/threatflow
GO     := go
GOFLAGS := -race

VERSION    := $(shell cat VERSION 2>/dev/null || echo dev)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
	-X github.com/opensecstack/threatflow/internal/version.Version=$(VERSION) \
	-X github.com/opensecstack/threatflow/internal/version.GitCommit=$(GIT_COMMIT) \
	-X github.com/opensecstack/threatflow/internal/version.BuildDate=$(BUILD_DATE)

## build: Compile the threatflow binary
build:
	CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/threatflow

## test: Run unit tests with race detector (no live DB required)
test:
	$(GO) test $(GOFLAGS) ./... -count=1 -timeout=5m

## test-integration: Run DB-backed integration tests (needs THREATFLOW_TEST_DB_URL)
test-integration:
	@if [ -z "$$THREATFLOW_TEST_DB_URL" ]; then \
		echo "ERROR: THREATFLOW_TEST_DB_URL must be set (e.g. postgres://threatflow:threatflow@127.0.0.1:5433/threatflow?sslmode=disable)"; \
		exit 1; \
	fi
	$(GO) test $(GOFLAGS) -tags integration ./... -count=1 -timeout=10m

## test-e2e: Alias for test-integration — runs the full-stack HTTP e2e test.
test-e2e: test-integration

## test-all: Unit + integration in one shot
test-all: test test-integration

## test-cover: Run unit tests with coverage report
test-cover:
	$(GO) test $(GOFLAGS) ./... -coverprofile=coverage.out -covermode=atomic
	$(GO) tool cover -func=coverage.out
	@echo "---"
	@$(GO) tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

## test-cover-integration: Coverage across unit + integration
test-cover-integration:
	@if [ -z "$$THREATFLOW_TEST_DB_URL" ]; then \
		echo "ERROR: THREATFLOW_TEST_DB_URL must be set"; \
		exit 1; \
	fi
	$(GO) test $(GOFLAGS) -tags integration ./... -coverprofile=coverage.out -covermode=atomic
	$(GO) tool cover -func=coverage.out
	@$(GO) tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

## bench: Run Go benchmarks (parser, signing, ATT&CK merge)
bench:
	$(GO) test -run=^$$ -bench=. -benchmem ./internal/stix ./internal/webhook ./internal/attack

## release-notes: Extract the most recent release section from CHANGELOG.md
release-notes:
	@awk '/^## \[/{if(n)exit; n=1; print; next} n' CHANGELOG.md

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## fmt: Format all Go source files
fmt:
	$(GO) fmt ./...
	goimports -w .

## vet: Run go vet
vet:
	$(GO) vet ./...

## security: Run govulncheck and gosec
security:
	govulncheck ./...
	gosec -fmt json -out gosec-results.json -stdout -verbose=text ./...

## run: Start the server in development mode
run:
	$(GO) run ./cmd/threatflow serve --log-format text --log-level debug

## clean: Remove build artifacts
clean:
	rm -rf bin/ coverage.out gosec-results.json tmp/

## docker: Build the production Docker image
docker:
	docker build -t threatflow:latest .

## docker-dev: Build and run with hot-reload
docker-dev:
	docker compose -f docker-compose.dev.yml up --build

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
