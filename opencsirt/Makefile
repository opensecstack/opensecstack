# OpenCSIRT Makefile
#
# IMG_TAG  — tag applied to images built by `docker-build`. Defaults
#            to `dev` for local builds; CI overrides with the commit
#            SHA / release tag.
# IMG_REPO — registry path. Defaults to ghcr.io/opensecstack.

IMG_TAG  ?= dev
IMG_REPO ?= ghcr.io/opensecstack

DB_URL ?= postgres://opencsirt:opencsirt@localhost:5432/opencsirt?sslmode=disable

.PHONY: help build api advisory web test test-postgres vet lint \
        docker-build dev migrate-up migrate-down clean

help:
	@echo "OpenCSIRT — make targets"
	@echo "  build              build api + advisory wheel + web"
	@echo "  api                build Go API binary (cmd/opencsirt)"
	@echo "  advisory           build Python advisory wheel (python/)"
	@echo "  web                build React dashboard (web/)"
	@echo "  test               run unit tests (Go + Python + web)"
	@echo "  test-postgres      run -tags integration Go tests against a real Postgres"
	@echo "  vet                go vet ./..."
	@echo "  lint               run linters across the tree (go vet + ruff + eslint)"
	@echo "  docker-build       build container images (tag=\$$IMG_TAG, repo=\$$IMG_REPO)"
	@echo "  dev                docker compose up -d (full local stack)"
	@echo "  migrate-up         apply Postgres migrations against \$$DB_URL"
	@echo "  migrate-down       roll back the most recent migration"
	@echo "  clean              remove bin/, web/dist, python/.venv, *.test"

build: api advisory web

api:
	go build -o bin/opencsirt ./cmd/opencsirt

advisory:
	cd python && python -m build --wheel

web:
	cd web && npm ci && npm run build

test:
	go test ./...
	cd python && pytest
	cd web && npm test

# test-postgres runs the Go integration suite that requires a live
# Postgres. Set OPENCSIRT_TEST_DB_URL to the test DSN; the tests skip
# silently when it is unset (matching the openscrub / irflow pattern).
test-postgres:
	@test -n "$$OPENCSIRT_TEST_DB_URL" || \
	  (echo "OPENCSIRT_TEST_DB_URL is unset — see docs/operator-handbook.md"; exit 1)
	go test -tags=integration -count=1 ./internal/db/...

vet:
	go vet ./...

lint:
	go vet ./...
	cd python && ruff check .
	cd web && npm run lint

docker-build:
	docker build -f cmd/opencsirt/Dockerfile \
	  -t $(IMG_REPO)/opencsirt-api:$(IMG_TAG) .
	docker build -f python/Dockerfile \
	  -t $(IMG_REPO)/opencsirt-advisory:$(IMG_TAG) python
	docker build -f web/Dockerfile \
	  -t $(IMG_REPO)/opencsirt-web:$(IMG_TAG) web

dev:
	docker compose -f deploy/docker-compose.yml up -d

migrate-up:
	@command -v migrate >/dev/null || \
	  (echo "migrate not installed: go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"; exit 1)
	migrate -path migrations -database "$(DB_URL)" up

migrate-down:
	@command -v migrate >/dev/null || \
	  (echo "migrate not installed"; exit 1)
	migrate -path migrations -database "$(DB_URL)" down 1

clean:
	rm -rf bin/ web/dist python/.venv python/dist python/build *.test coverage.*
