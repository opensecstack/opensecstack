VERSION ?= dev
DB_URL  ?= postgres://sinauth:sinauth@localhost:5432/sinauth?sslmode=disable

LDFLAGS := -X github.com/opensecstack/sinauth/internal/version.Version=$(VERSION) \
           -X github.com/opensecstack/sinauth/internal/version.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo none) \
           -X github.com/opensecstack/sinauth/internal/version.Date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)

.PHONY: build test lint migrate dev docker-build keys-generate web-install web-dev web-build

build:
	go build -ldflags="$(LDFLAGS)" -o bin/sinauth ./cmd/sinauth

test:
	go test ./...

lint:
	golangci-lint run

migrate:
	go run ./cmd/sinauth migrate --db-url=$(DB_URL)

dev:
	go run ./cmd/sinauth serve --env development

docker-build:
	docker build -t sinauth:$(VERSION) .

keys-generate:
	go run ./cmd/sinauth keys generate

web-install:
	cd web && npm install

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build
