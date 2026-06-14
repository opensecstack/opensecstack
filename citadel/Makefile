.PHONY: run build test bench migrate docker-up docker-down

## run: start CITADEL locally (requires postgres running)
run:
	CITADEL_DB_URL="postgres://citadel:citadel_secret@localhost:5434/citadel?sslmode=disable" \
	go run ./cmd/citadel

## build: compile CITADEL binary
build:
	go build -ldflags="\
	  -X github.com/opensecstack/citadel/internal/version.Version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev) \
	  -X github.com/opensecstack/citadel/internal/version.GitCommit=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown) \
	  -X github.com/opensecstack/citadel/internal/version.BuildDate=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	  -o bin/citadel ./cmd/citadel

## test: run all tests
test:
	go test ./... -v -count=1

## bench: run all benchmarks (Session 4)
bench:
	go test -tags bench -bench=. -benchmem -count=10 ./benches/

## migrate: apply migrations to local postgres
migrate:
	psql "postgres://citadel:citadel_secret@localhost:5434/citadel?sslmode=disable" \
	  -f migrations/001_initial.sql

## docker-up: start CITADEL + postgres via docker-compose
docker-up:
	docker-compose up --build -d
	@echo "CITADEL running at http://localhost:8099/api/v1/health"

## docker-down: stop all containers
docker-down:
	docker-compose down -v

## health: check CITADEL health endpoint
health:
	curl -s http://localhost:8099/api/v1/health | python3 -m json.tool
