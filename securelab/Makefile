# SecureLab — Makefile
# Targets: build, test, run, docker-build, migrate, scenario-validate, lint
#
# SAFETY: 'make run' starts the API server in dev mode, localhost only.
# Never run against production. See docs/safety-controls.md.

.PHONY: build test run docker-build migrate scenario-validate lint clean help

# ─── Variables ────────────────────────────────────────────────────────────────

GO          := go
CARGO       := cargo
DOCKER      := docker
COMPOSE     := docker compose
GOFLAGS     := -trimpath
BINARY      := bin/securelab

API_HOST    := 127.0.0.1
API_PORT    := 8080

# ─── Default target ───────────────────────────────────────────────────────────

.DEFAULT_GOAL := help

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ─── Build ────────────────────────────────────────────────────────────────────

build: ## Build Go binary and Rust payload generator
	mkdir -p bin
	$(GO) build $(GOFLAGS) -o $(BINARY) ./cmd/securelab
	$(CARGO) build -p payload-gen --release

# ─── Test ─────────────────────────────────────────────────────────────────────

test: ## Run all Go tests (CGO_ENABLED=0 for Windows compat; integration excluded — needs DB)
	CGO_ENABLED=0 $(GO) test $(shell $(GO) list ./... | grep -v '/tests/integration') -count=1

# ─── Run ──────────────────────────────────────────────────────────────────────

run: ## Start API server in dev mode (localhost only)
	@echo "SAFETY WARNING: SecureLab contains offensive tooling."
	@echo "Ensure this environment is isolated. See docs/safety-controls.md"
	@echo ""
	SECURELAB_HTTP_ADDR=$(API_HOST):$(API_PORT) \
	SECURELAB_DEV_MODE=true \
	SECURELAB_CITADEL_DRY_RUN=true \
	$(GO) run ./cmd/securelab

# ─── Docker ───────────────────────────────────────────────────────────────────

docker-build: ## Build Docker images (api + web)
	$(DOCKER) build --target api -t ghcr.io/opensecstack/securelab:dev .
	$(DOCKER) build --target web -t ghcr.io/opensecstack/securelab-web:dev .

# ─── Database ─────────────────────────────────────────────────────────────────

migrate: ## Run database migrations
	$(GO) run ./cmd/migrate up

# ─── Scenario validation ──────────────────────────────────────────────────────

scenario-validate: ## Validate all scenario YAML files
	$(GO) test ./tests/scenarios/... -v -run TestValidateAllScenarios

# ─── Lint ─────────────────────────────────────────────────────────────────────

lint: ## Run golangci-lint, go vet, and cargo clippy
	$(GO) vet ./...
	golangci-lint run ./...
	$(CARGO) clippy -p payload-gen -- -D warnings
	cd web && npm run lint

# ─── Clean ────────────────────────────────────────────────────────────────────

clean: ## Remove build artifacts
	rm -rf bin/
	$(CARGO) clean -p payload-gen
	cd web && rm -rf dist node_modules
