# Testing IRFlow

IRFlow's test suite is split into three layers, each with a distinct
scope, speed, and dependency profile. Knowing which to run when is the
single biggest speed-up for contributors.

## Test layers

| Layer | Scope | Dependencies | Command |
|---|---|---|---|
| Unit | Single package, in-memory mocks | None | `make test` |
| Integration | Full service, real PostgreSQL | Docker + `docker-compose.test.yml` | `make test-integration` |
| HTTP E2E | API server end-to-end with real store | Same as integration | `make test-integration` (subset) |

Unit tests are the default. They run in a few seconds and produce
actionable failures immediately. Integration tests exist to catch the
gap between "the mock agreed" and "PostgreSQL actually behaves this
way" — run them before opening a PR that touches storage.

## Unit tests

```bash
make test
# equivalent to:
#   go test ./... -race -count=1
```

Coverage conventions:

- Tests live next to the code they exercise (`foo.go` → `foo_test.go`).
- HTTP handlers use `httptest.NewRequest` / `httptest.NewRecorder` with
  a fake `Service` or `Store`.
- Service-layer tests use the in-memory `Store` mock — the same mock
  is used by every service test so its behaviour is stable and trusted.
- The webhook package has table-driven tests covering every error
  sentinel (see [internal/webhook/hmac_test.go](../internal/webhook/hmac_test.go)).
- `-race` is on by default; races fail the build.

## Integration tests

Integration tests are gated behind the `integration` build tag. The
gate skips cleanly when `IRFLOW_TEST_DB_URL` is not set — safe to run
in environments without Docker.

### Bring up the test Postgres

```bash
make compose-test-up
# docker-compose -f docker-compose.test.yml up -d postgres
```

The shipped [docker-compose.test.yml](../docker-compose.test.yml)
exposes PostgreSQL on port **54832** (not the default 5432) so it does
not collide with any host-native Postgres.

### Run the suite

```bash
export IRFLOW_TEST_DB_URL="postgres://irflow:irflow_test@localhost:54832/irflow_test?sslmode=disable"
make test-integration
# equivalent to:
#   go test -tags integration -p 1 -count=1 ./...
```

The `-p 1` flag is **load-bearing**. Without it, Go runs packages in
parallel and their `TRUNCATE`-between-tests behaviour races against
each other, producing intermittent failures that look like data bugs.
Always keep `-p 1` for integration runs.

### What integration tests cover

- Migration replay on a fresh database (asserts idempotency).
- Store methods against real `pgx` types — catches JSONB encoding
  quirks the mock smooths over.
- End-to-end HTTP flow: create incident → submit action → verify
  action → state transition → retrieve.
- Webhook flow: real HMAC verification against a live request body.

## HTTP E2E scenarios

Inside the integration suite, the `cmd/irflow` package's test file
runs a real `api.Server` against the real DB and drives it with a
`testclient.Client`. This is the canonical coverage for:

- Router wiring and middleware composition.
- Error-response shape consistency.
- Metrics chicken-and-egg: `/health` is called before `/metrics` so
  the `irflow_http_requests_total` counter has at least one value
  when Prometheus scrapes it.

## Linting

```bash
make lint
# golangci-lint run ./...
```

Enforced checks (from `.golangci.yml`): `errcheck`, `gosec`,
`goimports`, `staticcheck`, `bodyclose`. Keep the lint output clean
before commit — CI fails on any new finding.

## Coverage

```bash
go test -cover ./...            # quick line coverage
go test -coverprofile=cov.out   ./...
go tool cover -html=cov.out     # open in browser
```

No coverage threshold is enforced — coverage is a signal, not a goal.
Aim for: every branch of service-layer logic covered by unit tests,
every handler covered by HTTP E2E.

## Running a single test

```bash
# Single package
go test ./internal/incident

# Single test by name
go test -run TestCreate_RejectsUnknownSeverity ./internal/incident

# Integration-tagged test
go test -tags integration -run TestEndToEnd_IncidentFlow ./cmd/irflow
```

## Benchmarks

IRFlow doesn't ship benchmarks in v1.0.0 — CITADEL owns the
performance-critical hot paths (MARSHAL, WORM). v1.1's "Performance
benchmarks" roadmap item will add end-to-end latency numbers.

## CI

GitHub Actions runs both layers against a matrix of Go versions:

```yaml
- run: make lint
- run: make test
- run: make compose-test-up
- run: make test-integration
```

See [.github/workflows/ci.yml](../.github/workflows/ci.yml). Failures
in either layer block the merge.

## Common pitfalls

- **Flaky integration tests**: almost always a missing `-p 1`. If you
  see intermittent `TRUNCATE` errors, check the flag first.
- **`tests skipped: IRFLOW_TEST_DB_URL not set`**: expected when you
  run `go test -tags integration` without exporting the env var.
- **Mock vs real divergence**: if unit tests pass but integration
  fails, the mock is too permissive. Tighten the mock; don't loosen
  the test.

## Related

- [CONTRIBUTING.md](../CONTRIBUTING.md) — PR checklist references these
- [Architecture](./architecture.md) — what the layers actually exercise
- [Deployment](./deployment.md) — docker-compose shape matches the test compose file
