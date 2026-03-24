# Contributing to APIGuard

Thank you for your interest in contributing to APIGuard!

## Before You Start

- Check existing [issues](https://github.com/opensecstack/apiguard/issues) and [discussions](https://github.com/opensecstack/apiguard/discussions)
- For large features, open a discussion first to align on approach
- For bugs, check if already reported

## Development Setup

See [docs/dev/setup.md](docs/dev/setup.md) for full setup instructions.

```bash
git clone https://github.com/opensecstack/apiguard
cd apiguard
cp .env.example .env
make dev
make test  # all tests must pass
```

## Commit Messages

Conventional Commits format required:

```
feat(parser): add support for OpenAPI 3.1 webhooks
fix(scanner): handle timeout on slow target APIs
docs(readme): update quick start instructions
```

## PR Requirements

- Tests for new code
- Documentation updated
- CHANGELOG.md entry
- No breaking changes without RFC
- CITADEL task ID in PR description if CITADEL is active

## Code Review

- Maintainers aim to review within 7 days
- Two approvals required for merge (one from a core maintainer)

## Rust Contributions

- Run `cargo fmt` and `cargo clippy` before submitting
- No new `unsafe` blocks without justification comment

## Go Contributions

- Run `gofmt` and `golangci-lint` before submitting
- Errors must be wrapped with context: `fmt.Errorf("context: %w", err)`

## First Contributions

Look for issues labelled `good first issue`. Mentorship available in Discord #contributors channel.
