# Contributing to sinauth

Thank you for your interest in contributing to sinauth.

## Getting started

1. Fork the repository and create a feature branch from `main`.
2. Install Go 1.25 and Docker.
3. Copy `.env.example` to `.env` and fill in local values.
4. Run `make keys-generate` to generate a local signing key.
5. Start the dev stack: `docker compose -f docker-compose.dev.yml up`.
6. Run migrations: `make migrate`.

## Code style

- Format all Go code with `gofmt` before committing.
- Pass `golangci-lint run` with zero warnings. The lint config is in `.golangci.yml`.
- Keep packages small and focused on a single responsibility.
- Avoid adding external dependencies without discussion — the current stack is intentionally minimal (Go stdlib + pgx + jwt + cobra).

## Tests

All changes must include tests. Run the test suite with:

```bash
make test
```

Integration tests require a running PostgreSQL instance (the dev Docker Compose stack provides one on port 5433).

## Pull requests

- Open one PR per logical change.
- Reference any related issue in the PR description.
- Ensure CI passes before requesting review.
- A maintainer will review and merge; do not self-merge.

## Commit messages

Use the imperative mood in the subject line (`Add PKCE verification`, not `Added PKCE verification`). Keep the subject under 72 characters. Add a body if the change needs context.

## Reporting bugs

Open a GitHub issue with:
- sinauth version (`make build && ./bin/sinauth version`)
- Go version (`go version`)
- Steps to reproduce
- Expected vs actual behavior

For security vulnerabilities, do **not** open a public issue. Email security@sin.to instead.
