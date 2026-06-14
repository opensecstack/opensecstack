# VertGuard Makefile
#
# IMG_TAG  — tag applied to images built by `docker` / signed by
#            `docker-sign`. Defaults to `dev` for local builds; CI
#            overrides it with the commit SHA / release tag.
# IMG_REPO — registry path. Defaults to ghcr.io/opensecstack.
# COSIGN   — cosign binary path (override for vendored installs).
# SYFT     — syft binary path.

IMG_TAG  ?= dev
IMG_REPO ?= ghcr.io/opensecstack
COSIGN   ?= cosign
SYFT     ?= syft

LDFLAGS := -X github.com/opensecstack/vertguard/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev) \
           -X github.com/opensecstack/vertguard/internal/version.GitCommit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown) \
           -X github.com/opensecstack/vertguard/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: help run build test test-integration test-fp test-ml test-postgres \
        lint sec-go sec-rust sec security \
        mod-tidy-check \
        rust-build rust-test \
        web-lint web-test web-typecheck web-build \
        migrate docker-up docker-down compose-test-up compose-test-down \
        docker docker-build docker-sbom docker-sign docker-release \
        health clean proto-gen

## help: show available targets
help:
	@echo "VertGuard — make targets"
	@echo "  run                start VertGuard locally against Postgres on :5438"
	@echo "  build              compile VertGuard server + CLI binaries"
	@echo "  test               run unit tests with race detector"
	@echo "  test-integration   run integration tests against live Postgres"
	@echo "  test-postgres      run -tags integration Go tests against a real Postgres (\$$VERTGUARD_TEST_DB_URL)"
	@echo "  test-fp            run false-positive regression suite"
	@echo "  test-ml            run Python ML accuracy tests"
	@echo "  mod-tidy-check     verify go.mod/go.sum are tidy (closes gap 7.3)"
	@echo "  lint               run golangci-lint + cargo clippy + eslint"
	@echo "  sec-go             gosec + govulncheck + staticcheck"
	@echo "  sec-rust           cargo audit + cargo deny"
	@echo "  sec / security     all security scanners"
	@echo "  rust-build         build Rust crates"
	@echo "  rust-test          test Rust crates"
	@echo "  web-lint           eslint over web/"
	@echo "  web-typecheck      tsc --noEmit over web/"
	@echo "  web-test           run web unit tests"
	@echo "  web-build          build the React dashboard"
	@echo "  docker             build container images (tag=\$$IMG_TAG, repo=\$$IMG_REPO) — build → SBOM → sign"
	@echo "  docker-build       build container images only"
	@echo "  docker-sbom        emit SBOM-spdx for each image into bin/sbom/"
	@echo "  docker-sign        cosign-sign each image (keyless OIDC) + attach SBOM attestation"
	@echo "  docker-release     explicit release umbrella (alias of docker)"
	@echo "  docker-up          start VertGuard + Postgres via docker-compose"
	@echo "  docker-down        stop all containers"
	@echo "  compose-test-up    start test Postgres for integration tests"
	@echo "  compose-test-down  stop test Postgres"
	@echo "  migrate            apply SQL migrations"
	@echo "  proto-gen          regenerate Go stubs from proto/ml/v1/inference.proto"
	@echo "  health             check VertGuard health endpoint"
	@echo "  clean              remove build artefacts"

## run: start VertGuard locally against Postgres on :5438
run:
	VERTGUARD_DB_URL="postgres://vertguard:vertguard_dev@localhost:5438/vertguard?sslmode=disable" \
	go run ./cmd/server

## build: compile VertGuard server + CLI binaries
build:
	go build -ldflags="$(LDFLAGS)" -o bin/vertguard-server ./cmd/server
	go build -ldflags="$(LDFLAGS)" -o bin/vertguard ./cmd/vertguard

## test: run unit tests (CGO_ENABLED=0 for Windows compat; -p 2 avoids timing flakes in ratelimit)
test:
	CGO_ENABLED=0 go test -count=1 -p 2 ./...

## test-integration: run integration tests against live Postgres (requires -p 1)
test-integration:
	go test -tags integration -p 1 -count=1 ./...

# test-postgres runs the Go integration suite that requires a live
# Postgres. Set VERTGUARD_TEST_DB_URL to the test DSN; without it the
# target fails loudly so CI cannot silently skip the suite.
test-postgres:
	@test -n "$$VERTGUARD_TEST_DB_URL" || \
	  (echo "VERTGUARD_TEST_DB_URL is unset — see docs/testing.md"; exit 1)
	go test -tags=integration -count=1 ./internal/db/...

## test-fp: run false-positive regression suite
test-fp:
	go test -tags fp -count=1 ./tests/fp/...

## test-ml: run Python ML accuracy tests (Phase 4.2+)
test-ml:
	cd python/ml_service && pytest tests/ -v

## mod-tidy-check: verify go.mod and go.sum are tidy (closes gap 7.3)
## Runs `go mod tidy` then fails if either file is modified.
## Matches the step in .github/workflows/ci.yml (go-mod-tidy job).
mod-tidy-check:
	go mod tidy
	git diff --exit-code go.mod go.sum

## lint: run golangci-lint + cargo clippy + eslint
lint:
	golangci-lint run ./...
	cd rust && cargo clippy --all-targets --all-features -- -D warnings
	cd web && npm run lint

# sec-go runs the three Go-side security scanners. Each is invoked
# only when its binary is present so a fresh checkout `make sec-go`
# fails loudly (with install hints) instead of silently passing.
sec-go:
	@command -v gosec >/dev/null || \
	  (echo "gosec not installed: go install github.com/securego/gosec/v2/cmd/gosec@latest"; exit 1)
	gosec -quiet -severity medium -confidence medium ./...
	@command -v govulncheck >/dev/null || \
	  (echo "govulncheck not installed: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1)
	govulncheck ./...
	@command -v staticcheck >/dev/null || \
	  (echo "staticcheck not installed: go install honnef.co/go/tools/cmd/staticcheck@latest"; exit 1)
	staticcheck ./...

sec-rust:
	@command -v cargo-audit >/dev/null || \
	  (echo "cargo-audit not installed: cargo install cargo-audit"; exit 1)
	cd rust && cargo audit
	@command -v cargo-deny >/dev/null && cd rust && cargo deny check || \
	  echo "cargo-deny not installed (skipping); install with: cargo install cargo-deny"

sec security: sec-go sec-rust

## rust-build: build Rust crates
rust-build:
	cd rust && cargo build --release

## rust-test: test Rust crates
rust-test:
	cd rust && cargo test

# Web targets delegate to the npm scripts in web/package.json so
# `make web-lint` and `cd web && npm run lint` stay equivalent.
web-lint:
	cd web && npm run lint

web-typecheck:
	cd web && npm run typecheck

web-test:
	cd web && npm test

web-build:
	cd web && npm run build

## migrate: apply SQL migrations
migrate:
	psql "$$VERTGUARD_DB_URL" -f internal/db/migrations/001_initial.sql

# `docker` is the supply-chain-aware umbrella: build → SBOM → sign.
# Each stage is also available standalone (docker-build, docker-sbom,
# docker-sign) so dev work can skip the supply-chain steps when the
# scanners are not installed locally — CI and release tagging always
# go through the umbrella so published artefacts are SBOMed and signed.
docker: docker-build docker-sbom docker-sign

docker-build:
	docker build -f Dockerfile \
	  -t $(IMG_REPO)/vertguard-server:$(IMG_TAG) .
	docker build -f python/Dockerfile \
	  -t $(IMG_REPO)/vertguard-ml:$(IMG_TAG) python

# docker-release is the explicit "this is going out the door" target —
# same pipeline as `docker`, kept under its own name so release.yml
# can refer to it semantically.
docker-release: docker-build docker-sbom docker-sign

# docker-sbom requires syft. Output is SPDX JSON, one per image, under
# bin/sbom/. Attach to the OCI manifest with `cosign attest --predicate`
# (see docker-sign).
docker-sbom:
	@command -v $(SYFT) >/dev/null || \
	  (echo "$(SYFT) not found — install from https://github.com/anchore/syft"; exit 1)
	@mkdir -p bin/sbom
	@for svc in server ml; do \
	  $(SYFT) $(IMG_REPO)/vertguard-$$svc:$(IMG_TAG) \
	    -o spdx-json=bin/sbom/vertguard-$$svc-$(IMG_TAG).spdx.json; \
	done

# docker-sign uses cosign keyless (sigstore OIDC). Requires that the
# images already exist locally AND have been pushed to a registry that
# supports cosign attestations (ghcr.io, ECR, GAR, …). Set
# COSIGN_EXPERIMENTAL=1 in CI or pass --yes to this target.
docker-sign:
	@command -v $(COSIGN) >/dev/null || \
	  (echo "$(COSIGN) not found — install from https://github.com/sigstore/cosign"; exit 1)
	@for svc in server ml; do \
	  $(COSIGN) sign --yes $(IMG_REPO)/vertguard-$$svc:$(IMG_TAG); \
	  if [ -f bin/sbom/vertguard-$$svc-$(IMG_TAG).spdx.json ]; then \
	    $(COSIGN) attest --yes --predicate bin/sbom/vertguard-$$svc-$(IMG_TAG).spdx.json \
	      --type spdxjson $(IMG_REPO)/vertguard-$$svc:$(IMG_TAG); \
	  fi; \
	done

## docker-up: start VertGuard + Postgres via docker-compose
docker-up:
	docker compose up --build -d
	@echo "VertGuard running at http://localhost:8091/api/v1/health"

## docker-down: stop all containers
docker-down:
	docker compose down -v

## compose-test-up: start test Postgres for integration tests
compose-test-up:
	docker compose -f docker-compose.test.yml up -d postgres

## compose-test-down: stop test Postgres
compose-test-down:
	docker compose -f docker-compose.test.yml down -v

## health: check VertGuard health endpoint
health:
	curl -sf http://localhost:8091/api/v1/health | python3 -m json.tool || echo "VertGuard not responding"

## proto-gen: regenerate Go stubs from proto/ml/v1/inference.proto
##            Requires `protoc` on PATH. The plugin binaries are
##            fetched on-demand via `go run` so contributors don't
##            need to install protoc-gen-go / protoc-gen-go-grpc
##            manually. Output lands in internal/ml/pb/.
proto-gen:
	protoc --proto_path=proto \
		--plugin=protoc-gen-go=$$(go env GOPATH)/bin/protoc-gen-go \
		--plugin=protoc-gen-go-grpc=$$(go env GOPATH)/bin/protoc-gen-go-grpc \
		--go_out=. --go_opt=module=github.com/opensecstack/vertguard \
		--go-grpc_out=. --go-grpc_opt=module=github.com/opensecstack/vertguard \
		proto/ml/v1/inference.proto || ( \
		echo "protoc plugins missing — installing into GOPATH/bin"; \
		go install google.golang.org/protobuf/cmd/protoc-gen-go@latest; \
		go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest; \
		protoc --proto_path=proto \
			--go_out=. --go_opt=module=github.com/opensecstack/vertguard \
			--go-grpc_out=. --go-grpc_opt=module=github.com/opensecstack/vertguard \
			proto/ml/v1/inference.proto )

## clean: remove build artefacts
clean:
	rm -rf bin/
	cd rust && cargo clean
