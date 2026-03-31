.PHONY: help test test-go test-python test-rust lint lint-go lint-python lint-rust fmt fmt-go fmt-python fmt-rust audit audit-go audit-python audit-rust clean publish-python release-go changelog

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

test: test-go test-python test-rust ## Run all SDK tests

test-go: ## Run Go SDK tests with coverage
	cd go && go test ./... -coverprofile=coverage.out -covermode=atomic && go tool cover -func=coverage.out

test-python: ## Run Python SDK tests with coverage
	cd python && pytest tests/ -v --cov=opensecstack --cov-report=term-missing --cov-fail-under=70

test-rust: ## Run Rust SDK tests
	cd rust && cargo test --all-features

lint: lint-go lint-python lint-rust ## Run all linters

lint-go: ## Lint Go SDK
	cd go && go vet ./... && (which golangci-lint && golangci-lint run || true)

lint-python: ## Lint Python SDK
	cd python && black --check opensecstack/ && isort --check-only opensecstack/ && flake8 opensecstack/ --max-line-length=120 && mypy opensecstack/ --ignore-missing-imports

lint-rust: ## Lint Rust SDK
	cd rust && cargo fmt --check && cargo clippy --all-targets -- -D warnings

fmt: fmt-go fmt-python fmt-rust ## Format all SDK code

fmt-go: ## Format Go SDK
	cd go && gofmt -w .

fmt-python: ## Format Python SDK
	cd python && black opensecstack/ tests/ && isort opensecstack/ tests/

fmt-rust: ## Format Rust SDK
	cd rust && cargo fmt

audit: audit-go audit-python audit-rust ## Run security audits

audit-go: ## Audit Go dependencies
	cd go && (which govulncheck && govulncheck ./... || go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...)

audit-python: ## Audit Python dependencies
	cd python && pip-audit -r requirements.txt

audit-rust: ## Audit Rust dependencies
	cd rust && cargo audit

clean: ## Remove build artifacts
	cd go && rm -f coverage.out
	cd python && rm -rf .pytest_cache __pycache__ htmlcov .coverage dist build *.egg-info
	cd rust && cargo clean

publish-python: ## Build and publish Python SDK to PyPI (requires PYPI_TOKEN env var)
	@if [ -z "$(PYPI_TOKEN)" ]; then \
		echo "ERROR: PYPI_TOKEN is not set. Export it before running this target."; \
		exit 1; \
	fi
	cd python && pip install hatch && hatch build
	cd python && HATCH_INDEX_AUTH="$(PYPI_TOKEN)" hatch publish --repo main dist/

release-go: ## Create and push a Go SDK release tag (usage: make release-go VERSION=v0.2.0)
	@if [ -z "$(VERSION)" ]; then \
		echo "ERROR: VERSION is not set. Usage: make release-go VERSION=v0.2.0"; \
		exit 1; \
	fi
	@echo "Tagging Go SDK release sdk/go/$(VERSION)"
	git tag sdk/go/$(VERSION)
	git push origin sdk/go/$(VERSION)
	@echo "Tag pushed. The sdk-go-publish workflow will run tests automatically."

changelog: ## Remind developer to update CHANGELOG.md files before releasing
	@echo "---------------------------------------------------------------"
	@echo "  Pre-release checklist: update CHANGELOG.md"
	@echo "---------------------------------------------------------------"
	@echo "  Python SDK : sdk/python/CHANGELOG.md"
	@echo "  Go SDK     : sdk/go/CHANGELOG.md"
	@echo ""
	@echo "  Commit the changelog, then run the appropriate release target:"
	@echo "    make publish-python PYPI_TOKEN=<token>"
	@echo "    make release-go VERSION=v0.2.0"
	@echo "---------------------------------------------------------------"
