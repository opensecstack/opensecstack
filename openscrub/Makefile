# OpenScrub Makefile
#
# IMG_TAG  — tag applied to images built by `docker` / signed by
#            `docker-sign`. Defaults to `dev` for local builds; CI
#            overrides it with the commit SHA / release tag.
# IMG_REPO — registry path. Defaults to ghcr.io/opensecstack.

IMG_TAG  ?= dev
IMG_REPO ?= ghcr.io/opensecstack
COSIGN   ?= cosign
SYFT     ?= syft

.PHONY: help build api loader ebpf web test test-integration test-postgres \
        docker docker-build docker-sbom docker-sign docker-release \
        compose-up compose-down lint sec-go sec-rust sec security

help:
	@echo "OpenScrub — make targets"
	@echo "  build              build api + loader + ebpf + web"
	@echo "  api                build Go API binary"
	@echo "  loader             build Rust loader"
	@echo "  ebpf               build eBPF/C program"
	@echo "  web                build React dashboard"
	@echo "  test               run unit tests (Go + Rust + web)"
	@echo "  test-integration   run end-to-end integration tests"
	@echo "  test-postgres      run -tags integration Go tests against a real Postgres"
	@echo "  docker             build container images (tag=\$$IMG_TAG, repo=\$$IMG_REPO)"
	@echo "  docker-sbom        emit SBOM-spdx for each image into bin/sbom/"
	@echo "  docker-sign        cosign-sign each image (keyless OIDC)"
	@echo "  compose-up         docker compose up -d"
	@echo "  compose-down       docker compose down -v"
	@echo "  lint               run linters across the tree (go vet + clippy + eslint)"
	@echo "  sec-go             gosec + govulncheck + staticcheck"
	@echo "  sec-rust           cargo audit + cargo deny (if installed)"
	@echo "  sec / security     all security scanners"

build: ebpf loader api web

api:
	go build -o bin/openscrub ./cmd/openscrub

loader:
	cd rust/dataplane && cargo build --release

ebpf:
	$(MAKE) -C ebpf

web:
	cd web && npm ci && npm run build

test:
	go test ./...
	cd rust/dataplane && cargo test
	cd web && npm test

test-integration:
	bash tests/integration/run.sh

# test-postgres runs the Go integration suite that requires a live
# Postgres. Set OPENSCRUB_TEST_DB_URL to the test DSN; the tests skip
# silently when it is unset (matching the cyberpath / irflow pattern).
test-postgres:
	@test -n "$$OPENSCRUB_TEST_DB_URL" || \
	  (echo "OPENSCRUB_TEST_DB_URL is unset — see docs/testing.md"; exit 1)
	go test -tags=integration -count=1 ./internal/db/...

# `docker` is the supply-chain-aware umbrella: build → SBOM → sign.
# Each stage is also available standalone (docker-build, docker-sbom,
# docker-sign) so dev work can skip the supply-chain steps when the
# scanners are not installed locally — CI and release tagging always
# go through the umbrella so published artefacts are SBOMed and signed.
docker: docker-build docker-sbom docker-sign

docker-build:
	docker build -f cmd/openscrub/Dockerfile \
	  -t $(IMG_REPO)/openscrub-api:$(IMG_TAG) .
	# Image name follows the Cargo crate name (`openscrub-dataplane`);
	# the binary inside is still `openscrub-loader`. Compose + Helm
	# pull this same name.
	docker build -f rust/dataplane/Dockerfile \
	  -t $(IMG_REPO)/openscrub-dataplane:$(IMG_TAG) rust/dataplane
	docker build -f web/Dockerfile \
	  -t $(IMG_REPO)/openscrub-web:$(IMG_TAG) web

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
	@for svc in api dataplane web; do \
	  $(SYFT) $(IMG_REPO)/openscrub-$$svc:$(IMG_TAG) \
	    -o spdx-json=bin/sbom/openscrub-$$svc-$(IMG_TAG).spdx.json; \
	done

# docker-sign uses cosign keyless (sigstore OIDC). Requires that the
# images already exist locally AND have been pushed to a registry that
# supports cosign attestations (ghcr.io, ECR, GAR, …). Set
# COSIGN_EXPERIMENTAL=1 in CI or pass --yes to this target.
docker-sign:
	@command -v $(COSIGN) >/dev/null || \
	  (echo "$(COSIGN) not found — install from https://github.com/sigstore/cosign"; exit 1)
	@for svc in api dataplane web; do \
	  $(COSIGN) sign --yes $(IMG_REPO)/openscrub-$$svc:$(IMG_TAG); \
	  if [ -f bin/sbom/openscrub-$$svc-$(IMG_TAG).spdx.json ]; then \
	    $(COSIGN) attest --yes --predicate bin/sbom/openscrub-$$svc-$(IMG_TAG).spdx.json \
	      --type spdxjson $(IMG_REPO)/openscrub-$$svc:$(IMG_TAG); \
	  fi; \
	done

compose-up:
	docker compose -f deploy/docker-compose.yml up -d

compose-down:
	docker compose -f deploy/docker-compose.yml down -v

lint:
	go vet ./...
	cd rust/dataplane && cargo clippy -- -D warnings
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
	cd rust/dataplane && cargo audit
	@command -v cargo-deny >/dev/null && cd rust/dataplane && cargo deny check || \
	  echo "cargo-deny not installed (skipping); install with: cargo install cargo-deny"

sec security: sec-go sec-rust
