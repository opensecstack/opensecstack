.PHONY: build test lint fmt vet tidy docker-build

BINARY := community-server
MODULE  := github.com/opensecstack/community

build:
	go build -o bin/$(BINARY) ./cmd/server

test:
	go test ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

tidy:
	go mod tidy

docker-build:
	docker build -t opensecstack/community:dev .

web-install:
	cd web && npm install

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build

web-typecheck:
	cd web && npm run typecheck
