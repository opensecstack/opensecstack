# Contributing to ThreatFlow

Thank you for your interest in contributing to ThreatFlow. This guide covers
development setup, coding conventions, and the pull request process.

---

## Development Setup

### Prerequisites

- Go 1.22+
- PostgreSQL 16+ (local or Docker)
- Docker & Docker Compose (for integration tests)
- golangci-lint (for linting)

### Quick Start

```bash
# Clone and enter directory
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/threatflow

# Start dependencies
docker compose -f ../deploy/docker-compose.dev.yml up -d postgres redis

# Run database migrations
go run ./cmd/threatflow migrate

# Start in development mode
THREATFLOW_LOG_LEVEL=debug go run ./cmd/threatflow serve
```

The service starts on port 8091 by default. Verify with:

```bash
curl http://localhost:8091/api/v1/health
# {"service":"threatflow","status":"ok"}
```

### Running Tests

```bash
# Unit tests
go test ./...

# With race detector
go test -race ./...

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Integration tests (requires PostgreSQL)
THREATFLOW_DB_URL="postgres://threatflow:test@localhost:5432/threatflow_test?sslmode=disable" \
  go test -tags integration ./...
```

### Linting

```bash
# Install golangci-lint (if not already installed)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
golangci-lint run ./...
```

---

## Code Style

- **gofmt** -- all code must be formatted with `gofmt`. CI rejects unformatted code.
- **golangci-lint** -- no lint errors allowed. The `.golangci.yml` config at the
  repo root defines the enabled linters.
- **Naming**: follow Go conventions (exported = PascalCase, unexported = camelCase).
- **Errors**: wrap with `fmt.Errorf("context: %w", err)`. Never discard errors silently.
- **Context**: pass `context.Context` as the first parameter to any function that
  does I/O or may be cancelled.
- **Logging**: use `zap.Logger` (structured, JSON). Do not use `log.Println` or `fmt.Printf`
  for operational logs.
- **Comments**: exported functions and types must have doc comments starting with the
  identifier name.

---

## Architecture Guidelines

- Domain logic lives in `internal/` packages
- HTTP handlers live in `internal/api/handlers/`
- Database operations live in `internal/db/`
- Configuration is loaded via Viper (env vars with `THREATFLOW_` prefix)
- No global state -- pass dependencies via constructor injection
- Interfaces are defined by the consumer, not the implementer
- External service calls are wrapped in client packages under `internal/client/`

### Package Layout

```
cmd/
  threatflow/          # CLI entrypoint (Cobra)
internal/
  api/
    handlers/          # HTTP handler functions
    middleware/         # Auth, logging, CORS
    router.go          # Route registration
  config/              # Viper-based configuration
  db/                  # PostgreSQL queries and migrations
  feed/                # Feed polling implementations
  ioc/                 # IOC types, validation, deduplication
  stix/                # STIX 2.1 mapping and serialisation
  integration/         # Platform integrations (IRFlow, APIGuard, NIS2Compass)
  client/              # HTTP clients for external services
docs/                  # Documentation
```

---

## How to Add a New Feed Type

1. Create `internal/feed/<type>.go` implementing the `FeedPoller` interface:

   ```go
   type FeedPoller interface {
       Poll(ctx context.Context, feed *config.FeedConfig) ([]ioc.RawIOC, error)
       Type() string
   }
   ```

2. Add the configuration struct in `internal/config/config.go`
3. Register the feed type in `internal/feed/registry.go`
4. Add tests in `internal/feed/<type>_test.go` (unit tests with recorded HTTP responses)
5. Update `docs/ioc-feeds.md` with feed documentation
6. Add example configuration to README.md

### Testing Feed Implementations

Use `net/http/httptest` to record and replay HTTP responses:

```go
func TestMyFeedPoller_Poll(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write(loadTestFixture(t, "testdata/myfeed_response.json"))
    }))
    defer srv.Close()

    poller := NewMyFeedPoller()
    cfg := &config.FeedConfig{URL: srv.URL}
    iocs, err := poller.Poll(context.Background(), cfg)
    require.NoError(t, err)
    assert.Len(t, iocs, 5)
}
```

---

## How to Add a New IOC Type

1. Add the type constant to `internal/ioc/types.go`
2. Add STIX 2.1 mapping in `internal/stix/mapper.go`
3. Add validation rules in `internal/ioc/validator.go`
4. Update database schema if new fields are needed (see [migrations.md](migrations.md))
5. Add tests for ingestion, validation, and STIX mapping
6. Update `docs/data-model.md` and `docs/stix-integration.md`

---

## How to Add a New Integration

1. Create `internal/integration/<platform>.go`
2. Implement webhook handler in `internal/api/handlers/`
3. Add configuration for the integration (env vars with `THREATFLOW_` prefix)
4. Write integration tests with a mock server
5. Ensure CITADEL WORM events are emitted for any state-changing operations
6. Document in `docs/` and update the README integration table

---

## Commit Message Format

```
<type>(<scope>): <description>

type: feat, fix, docs, test, refactor, chore
scope: api, feed, stix, db, config, ci
```

Examples:

- `feat(feed): add MISP JSON importer`
- `fix(stix): handle missing confidence field in TAXII response`
- `docs(api): add pagination examples to IOC list endpoint`
- `test(db): add migration rollback tests`
- `refactor(ioc): extract validation into dedicated package`
- `chore(ci): update golangci-lint to v1.58`

### Commit Scope Reference

| Scope    | Covers                                              |
|----------|-----------------------------------------------------|
| `api`    | HTTP handlers, middleware, router                   |
| `feed`   | Feed polling, ingestion pipeline                    |
| `stix`   | STIX 2.1 mapping, bundle generation, TAXII client   |
| `db`     | Database queries, migrations, schema changes        |
| `ioc`    | IOC types, validation, deduplication                |
| `config` | Configuration loading, environment variables        |
| `ci`     | CI/CD pipeline, GitHub Actions, Docker              |
| `citadel`| CITADEL WORM/MARSHAL integration                    |

---

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Write tests first (TDD encouraged)
4. Ensure all tests pass: `go test -race ./...`
5. Ensure lint passes: `golangci-lint run`
6. Open PR against the `develop` branch with a description of changes
7. Wait for 1 approval from a maintainer
8. Squash and merge

### PR Title Format

Use the same format as commit messages:

```
feat(feed): add MISP JSON importer
```

### PR Description Template

```markdown
## What

Brief description of the change.

## Why

Motivation and context.

## How

Implementation approach (if non-obvious).

## Testing

How you tested the change.

## Checklist

- [ ] Tests cover the change
- [ ] No new lint warnings
- [ ] Documentation updated if API changed
- [ ] CITADEL WORM events emitted for new mutations
```

---

## Code Review Checklist

Reviewers will evaluate PRs against these criteria:

- [ ] Tests cover the change
- [ ] No new lint warnings
- [ ] Documentation updated if API changed
- [ ] CHANGELOG.md updated
- [ ] CITADEL WORM events emitted for new mutations
- [ ] Error messages are actionable (include what failed, why, and what to do)
- [ ] No secrets or credentials in code
- [ ] Context propagation: `context.Context` passed through call chain
- [ ] Graceful degradation: external service failures handled without panic
- [ ] Database queries use parameterised statements (no SQL injection)

---

## Reporting Issues

Open a GitHub issue with the following information:

- ThreatFlow version (`curl http://localhost:8091/api/v1/version`)
- Steps to reproduce
- Expected vs. actual behaviour
- Relevant logs (redact any secrets)

For security vulnerabilities, do not open a public issue. Email
security@opensecstack.dev instead.

---

## Licence

By contributing, you agree that your contributions will be licensed under
Apache 2.0 (see [LICENSE](../../LICENSE)).

---

## Further Reading

- [Architecture](architecture.md) -- system design and component interactions
- [API Reference](api-reference.md) -- HTTP endpoint documentation
- [Data Model](data-model.md) -- database schema
- [Migrations](migrations.md) -- database migration procedures
- [CITADEL Integration](citadel-integration.md) -- WORM logging and MARSHAL governance
