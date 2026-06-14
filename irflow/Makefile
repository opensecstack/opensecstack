.PHONY: build test test-integration lint run migrate clean compose-test-up compose-test-down

BINARY   := irflow
PKG      := ./cmd/irflow
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VPKG     := github.com/opensecstack/opensecstack/irflow/internal/version
LDFLAGS  := -ldflags "-X $(VPKG).Version=$(VERSION) -X $(VPKG).GitCommit=$(COMMIT) -X $(VPKG).BuildDate=$(BUILD_DATE)"

build:
	go build $(LDFLAGS) -o bin/$(BINARY) $(PKG)

test:
	go test -race -cover ./...

# Run integration tests (requires a PostgreSQL reachable via IRFLOW_TEST_DB_URL).
# Start one locally with `make compose-test-up` first.
IRFLOW_TEST_DB_URL ?= postgres://irflow:irflow_test@localhost:54832/irflow_test?sslmode=disable
# -p 1 serialises test packages; required because every integration package
# truncates the same shared database between tests.
test-integration:
	IRFLOW_TEST_DB_URL="$(IRFLOW_TEST_DB_URL)" \
		go test -tags=integration -p 1 -count=1 -timeout=5m ./...

compose-test-up:
	docker compose -f docker-compose.test.yml up -d
	@echo "postgres-test ready at localhost:54832 (db=irflow_test, user=irflow)"

compose-test-down:
	docker compose -f docker-compose.test.yml down -v

lint:
	golangci-lint run ./...

run: build
	./bin/$(BINARY) serve

migrate: build
	./bin/$(BINARY) migrate

clean:
	rm -rf bin/
