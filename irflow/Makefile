.PHONY: build test lint run migrate clean

BINARY   := irflow
PKG      := ./cmd/irflow
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
LDFLAGS  := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/$(BINARY) $(PKG)

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

run: build
	./bin/$(BINARY) serve

migrate: build
	./bin/$(BINARY) migrate

clean:
	rm -rf bin/
