# ThreatFlow Testing Guide

This document describes the testing strategy, conventions, and patterns used in ThreatFlow.

---

## Overview

ThreatFlow uses Go's standard `testing` package exclusively -- no external test frameworks or assertion libraries. Tests are organized into three tiers:

| Tier | Tag | Dependencies | Speed | CI Stage |
|------|-----|-------------|-------|----------|
| Unit | *(none)* | None (mocks only) | <1s per package | Every push |
| Integration | `-tags integration` | PostgreSQL | <30s total | Every push |
| End-to-end | `-tags e2e` | Full service stack | <2min total | Merge to main |

---

## Test File Organization

Test files live next to the source they test, following standard Go conventions:

```
internal/
  api/handlers/
    health.go / health_test.go
    ioc.go    / ioc_test.go
  domain/
    ioc.go    / ioc_test.go
  store/postgres/
    ioc_store.go / ioc_store_test.go / ioc_store_integ_test.go
  feed/
    taxii/  client.go / client_test.go
    csv/    parser.go / parser_test.go
```

**Naming:** `*_test.go` for unit tests, `*_integ_test.go` (guarded by `//go:build integration`) for integration tests, `*_e2e_test.go` (guarded by `//go:build e2e`) for end-to-end tests.

---

## Unit Tests

Unit tests verify individual functions and handlers in isolation with no external services.

### Handler Tests

Handler tests use `net/http/httptest`. See `internal/api/handlers/ioc_test.go` for canonical examples.

```go
func TestIOCIngest_AcceptsValidJSON(t *testing.T) {
    h := NewIOC(zerolog.Nop())
    rec := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodPost, "/iocs",
        strings.NewReader(`{"type":"ipv4-addr","value":"198.51.100.42"}`))
    req.Header.Set("Content-Type", "application/json")

    h.Ingest(rec, req)

    if rec.Code != http.StatusAccepted {
        t.Fatalf("want 202, got %d; body: %s", rec.Code, rec.Body.String())
    }
}
```

Key conventions:
- `zerolog.Nop()` for silent loggers in tests.
- `httptest.NewRecorder()` to capture responses, `httptest.NewRequest()` to build requests.
- For URL params, inject a chi route context:

```go
rctx := chi.NewRouteContext()
rctx.URLParams.Add("id", "test-uuid")
req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
```

### Domain and Store Unit Tests

Domain tests verify validation and business logic. Store unit tests use mock implementations of the store interface (see Mocking Patterns below).

```go
func TestIOC_Validate_RejectsEmptyValue(t *testing.T) {
    ioc := domain.IOC{Type: "ipv4-addr", Value: ""}
    if err := ioc.Validate(); err == nil {
        t.Fatal("expected validation error for empty value")
    }
}
```

---

## Integration Tests

Integration tests run against a real PostgreSQL instance. They are guarded by the `integration` build tag and skipped in default `go test` runs.

**Prerequisites:** PostgreSQL 16 (local or Docker), database `threatflow_test` with migrations applied, `THREATFLOW_TEST_DB_URL` env var set.

```bash
# Start test database
docker run -d --name tf-test-pg \
    -e POSTGRES_DB=threatflow_test -e POSTGRES_USER=threatflow \
    -e POSTGRES_PASSWORD=testpass -p 5433:5432 postgres:16-alpine

# Apply migrations and run tests
export THREATFLOW_TEST_DB_URL="postgres://threatflow:testpass@localhost:5433/threatflow_test?sslmode=disable"
go run ./cmd/threatflow migrate up --db-url "$THREATFLOW_TEST_DB_URL"
go test -tags integration -v -count=1 ./internal/...

docker rm -f tf-test-pg
```

### Writing Integration Tests

```go
//go:build integration

package postgres

func testDB(t *testing.T) *pgxpool.Pool {
    t.Helper()
    dbURL := os.Getenv("THREATFLOW_TEST_DB_URL")
    if dbURL == "" { t.Skip("THREATFLOW_TEST_DB_URL not set") }
    pool, err := pgxpool.New(context.Background(), dbURL)
    if err != nil { t.Fatalf("connect to test DB: %v", err) }
    t.Cleanup(func() { pool.Close() })
    return pool
}

func TestIOCStore_CreateAndFind(t *testing.T) {
    pool := testDB(t)
    store := NewIOCStore(pool)
    ctx := context.Background()

    ioc := &domain.IOC{Type: "ipv4-addr", Value: "198.51.100.42", Source: "integration-test"}
    if err := store.Create(ctx, ioc); err != nil { t.Fatalf("Create: %v", err) }
    if ioc.ID == "" { t.Fatal("expected ID after Create") }

    found, err := store.FindByID(ctx, ioc.ID)
    if err != nil { t.Fatalf("FindByID: %v", err) }
    if found.Value != ioc.Value { t.Errorf("want %q, got %q", ioc.Value, found.Value) }

    t.Cleanup(func() { pool.Exec(ctx, "DELETE FROM iocs WHERE id = $1", ioc.ID) })
}
```

Always clean up test data in `t.Cleanup` so tests are idempotent. Use unique source names for scoped cleanup. Never depend on row ordering without an explicit `ORDER BY`.

---

## End-to-End Tests

E2E tests spin up the full stack (HTTP server, PostgreSQL, optionally CITADEL) and exercise the API externally.

```bash
docker compose -f docker-compose.test.yml up -d
until curl -sf http://localhost:8091/api/v1/health; do sleep 1; done
go test -tags e2e -v -count=1 ./test/e2e/...
docker compose -f docker-compose.test.yml down -v
```

```go
//go:build e2e

package e2e

func TestE2E_IngestAndRetrieveIOC(t *testing.T) {
    resp := postJSON(t, baseURL+"/api/v1/iocs", map[string]string{
        "type": "domain-name", "value": "evil.example.com", "source": "e2e-test",
    })
    assertStatus(t, resp, http.StatusAccepted)

    resp = getJSON(t, baseURL+"/api/v1/iocs?value=evil.example.com")
    assertStatus(t, resp, http.StatusOK)
}
```

---

## Mocking Patterns

ThreatFlow uses interface-based mocking -- no external libraries (testify, gomock, etc.).

1. Define an interface in the consuming package.
2. Production code implements the interface.
3. Tests provide a stub struct with controllable fields.

```go
// Store interface (production)
type IOCStore interface {
    Create(ctx context.Context, ioc *domain.IOC) error
    FindByID(ctx context.Context, id string) (*domain.IOC, error)
    List(ctx context.Context, filter IOCFilter) ([]domain.IOC, int, error)
}

// Stub (tests)
type stubIOCStore struct {
    createErr  error
    findResult *domain.IOC
    findErr    error
}
func (s *stubIOCStore) Create(_ context.Context, _ *domain.IOC) error { return s.createErr }
func (s *stubIOCStore) FindByID(_ context.Context, _ string) (*domain.IOC, error) {
    return s.findResult, s.findErr
}
```

### Mocking CITADEL

```go
type CITADELClient interface {
    Evaluate(ctx context.Context, action, resource string) (Decision, error)
    LogEvent(ctx context.Context, event WORMEvent) error
}

type stubCITADEL struct { decision Decision; evalErr, logErr error }
func (s *stubCITADEL) Evaluate(_ context.Context, _, _ string) (Decision, error) {
    return s.decision, s.evalErr
}
func (s *stubCITADEL) LogEvent(_ context.Context, _ WORMEvent) error { return s.logErr }
```

---

## Test Fixtures and Helpers

Static test data lives in `testdata/` directories next to test files:

```
internal/feed/taxii/testdata/stix_bundle_valid.json
internal/feed/csv/testdata/alienvault_otx_sample.csv
```

```go
func loadFixture(t *testing.T, name string) []byte {
    t.Helper()
    data, err := os.ReadFile(filepath.Join("testdata", name))
    if err != nil { t.Fatalf("load fixture %s: %v", name, err) }
    return data
}
```

Shared helpers go in `internal/testutil/`:

```go
func SampleIOC(overrides ...func(*domain.IOC)) *domain.IOC {
    ioc := &domain.IOC{Type: "ipv4-addr", Value: "198.51.100.42", Source: "test", Confidence: 80}
    for _, fn := range overrides { fn(ioc) }
    return ioc
}
```

---

## Coverage Targets

| Package | Target |
|---------|--------|
| `internal/api/handlers` | 90% |
| `internal/domain` | 95% |
| `internal/store` | 80% |
| `internal/feed` | 80% |
| **Overall** | **80%** |

```bash
go test -coverprofile=coverage.out ./internal/...
go tool cover -html=coverage.out      # browser view
go tool cover -func=coverage.out | tail -1  # summary
```

---

## CI Configuration (GitHub Actions)

```yaml
name: ThreatFlow Tests
on:
  push:    { paths: ['threatflow/**'] }
  pull_request: { paths: ['threatflow/**'] }

jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go test -race -coverprofile=coverage.out ./internal/...
        working-directory: threatflow

  integration:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env: { POSTGRES_DB: threatflow_test, POSTGRES_USER: threatflow, POSTGRES_PASSWORD: testpass }
        ports: ['5432:5432']
        options: --health-cmd pg_isready --health-interval 5s --health-timeout 5s --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go run ./cmd/threatflow migrate up --db-url "$DB_URL"
        working-directory: threatflow
        env: { DB_URL: 'postgres://threatflow:testpass@localhost:5432/threatflow_test?sslmode=disable' }
      - run: go test -tags integration -race -v ./internal/...
        working-directory: threatflow
        env: { THREATFLOW_TEST_DB_URL: 'postgres://threatflow:testpass@localhost:5432/threatflow_test?sslmode=disable' }
```

---

## Checklist: New Handler Test

1. Create the handler method on the appropriate struct.
2. Create or update the corresponding `*_test.go` in the same package.
3. Write at minimum: **happy path** (valid input, expected status), **invalid input** (malformed JSON, 400), **not found** (missing resource, 404), and **store error** (simulated DB failure, 500).
4. For mutation endpoints, verify CITADEL WORM event emission via the stub client.
5. Run `go test -race ./internal/api/handlers/` and check coverage.

## Checklist: New Feed Type Test

1. Create `parser.go` with `Parse(reader io.Reader) ([]domain.IOC, error)`.
2. Add sample data to `testdata/` (realistic but sanitized).
3. Write tests for: valid feed, empty feed, malformed feed, partial feed (valid rows parsed, invalid rows warned).
4. For HTTP polling, use `httptest.NewServer` to simulate the remote endpoint.
5. Run `go test -race ./internal/...` to confirm no regressions.
