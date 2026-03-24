# Contributing to opensecstack

Thank you for your interest in contributing to opensecstack! This guide covers contributing to any platform in the ecosystem.

## Before You Start

1. Check existing [issues](https://github.com/opensecstack/opensecstack/issues) and [discussions](https://github.com/opensecstack/opensecstack/discussions)
2. For large features, open a discussion first to align on approach
3. For bugs, check if already reported
4. Read the platform-specific `CONTRIBUTING.md` in the relevant directory

## Development Setup

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Docker | 24+ | Local stack and test targets |
| Docker Compose | 2.24+ | Local orchestration |
| Go | 1.22+ | Backend services and CLIs |
| Rust | 1.76+ (stable) | Parsers, analysers, crypto |
| Node.js | 20+ LTS | React dashboards |
| Python | 3.12+ | Data science, reports, ML |
| PostgreSQL | 16+ | Via Docker (recommended) |

### Quick Start

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack

# Option 1: VS Code devcontainer (recommended — all tools pre-installed)
# Open in VS Code → "Reopen in Container"

# Option 2: Manual setup
make dev          # Start full local stack
make test         # Run all tests
```

## Commit Messages

Conventional Commits format is required across all platforms:

```
feat(apiguard/parser): add OpenAPI 3.1 webhook support
fix(irflow/notifications): correct NIS2 24h deadline calculation
docs(ecosystem): update architecture diagram with OpenCSIRT
chore(ci): add Rust clippy to PR checks
```

Format: `type(scope): description`

Types: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `perf`, `ci`

## Pull Request Requirements

- [ ] Tests for new code
- [ ] Documentation updated
- [ ] CHANGELOG.md entry in the relevant platform
- [ ] No breaking changes without RFC
- [ ] CITADEL task ID in PR description (if CITADEL is active)
- [ ] Passes `make lint` and `make test`

## Code Review

- Maintainers aim to review within 7 days
- Two approvals required for merge (one from a core maintainer)
- Security-sensitive changes require review from a security maintainer

## Language-Specific Guidelines

### Go
- Run `gofmt` and `golangci-lint` before submitting
- Wrap errors with context: `fmt.Errorf("context: %w", err)`

### Rust
- Run `cargo fmt` and `cargo clippy` before submitting
- No new `unsafe` blocks without justification comment
- All parser code must handle malformed input without panic

### Python
- Run `ruff` and `mypy` before submitting
- Type hints required for all public functions

### React/TypeScript
- Run `eslint` and `prettier` before submitting
- Components must be typed with TypeScript

## First Contributions

Look for issues labelled `good first issue` in any platform. Mentorship is available — ask in Discord #contributors channel.

## Contributor Licence Agreement (CLA)

By submitting a PR, you agree to the [CLA](CLA.md). This ensures that contributions can be distributed under the project's licences.
