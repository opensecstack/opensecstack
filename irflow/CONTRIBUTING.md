# Contributing to IRFlow

Thanks for considering a contribution — here's how the project expects work
to flow.

## Development setup

```bash
# Clone
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/irflow

# Copy the example env
cp .env.example .env

# Start the integration-test Postgres (optional, only needed for integration tests)
make compose-test-up

# Build + run unit tests
make build
make test
```

## Required tools

- Go 1.24+
- Docker + Docker Compose (only for integration tests)
- `golangci-lint` (for `make lint`)

## Code style

- `gofmt`-clean code (enforced by most IDEs and by `golangci-lint`).
- Prefer small, composable packages; keep cross-package dependencies a DAG.
- Errors: return, don't panic. Use `fmt.Errorf("%w: …", wrappedErr)` for
  typed error unwrapping. Sentinel errors go next to the exported types
  they relate to.
- Logging: structured via `zap`. Use fields (`zap.String`, `zap.Error`, …),
  not `fmt.Sprintf` inside messages.
- Comments: focus on *why*, not *what*. Name functions well instead of
  writing a paragraph explaining an obvious operation.

## Testing

| Command | Scope |
|---|---|
| `make test` | Unit tests only — fast, no Docker required |
| `make test-integration` | Full suite including HTTP E2E against live Postgres |
| `make lint` | `golangci-lint run ./...` |

- Unit tests live next to the code they exercise and run under the default
  Go build.
- Integration tests are gated behind the `integration` build tag and skip
  cleanly when `IRFLOW_TEST_DB_URL` is unset.
- HTTP handler tests use `httptest.NewRequest` / `httptest.NewRecorder`.
- Service tests use in-memory `Store` mocks; the E2E suite in
  `cmd/irflow` is the canonical integration coverage.

## Commit message format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(incident): auto-create incidents from APIGuard webhooks

CITADEL HARD_STOP events now produce a P1 incident via the new
webhook handler in internal/api/webhooks.go. See CHANGELOG.md for the
full behaviour matrix.

Closes #123
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`.

## Pull request checklist

- [ ] `make test` and `make lint` pass locally.
- [ ] `make test-integration` passes (or explain why it is not affected).
- [ ] New behaviour documented — `CHANGELOG.md` under `[Unreleased]` and
      `docs/api.md` if endpoints changed.
- [ ] Config changes reflected in `.env.example` and
      `internal/config/config.go`.
- [ ] Migrations bundled with equivalent `schema_migrations` bookkeeping
      (new `NNN_*.sql` file, never edit existing ones).
- [ ] No secrets committed; `.env` is gitignored.

## Release flow

1. Merge `main` features into an RC branch.
2. Bump `internal/version/version.go` and tag `vMAJOR.MINOR.PATCH`.
3. Update `CHANGELOG.md` — move `[Unreleased]` into the new version section
   with today's date.
4. `make test && make test-integration && make lint`.
5. Build release artifacts; `make build` honours `ldflags` for version
   injection.

## Code of conduct

Treat people kindly. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
