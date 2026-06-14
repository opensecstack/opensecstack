# VertGuard Testing Guide

VertGuard ships a three-tier test pyramid: fast in-package **unit tests**,
DB-backed **integration tests**, and full-stack **end-to-end tests** that
exercise the HTTP API, JWT auth, CITADEL WORM emission, and the ML model
hot path.

All tests run via `make`:

```bash
make test               # unit tests (no live DB / Redis required)
make test-integration   # DB-backed; needs VERTGUARD_TEST_DB_URL
make test-e2e           # full-stack HTTP + ML inference
make test-cover         # coverage report (unit only)
make test-all           # everything above
```

---

## 1. Unit Tests

Pure-Go tests with no external dependencies. Cover:

| Package | What it tests |
|---------|---------------|
| `internal/prompt` | Pattern matcher, ATLAS technique mapping, classification ladder |
| `internal/phishing` | URL parser, lookalike-domain detection, indicator scoring |
| `internal/identity` | Synthetic-identity scoring, replay-window logic |
| `internal/media` | C2PA manifest validation, TripleHash computation |
| `internal/threatfeed` | IOC dedup, ATLAS sync, severity escalation rules |
| `internal/auth` | JWT issue/verify, role hierarchy, denylist enforcement |
| `internal/citadel` | HMAC signing, fail-open / fail-closed, async drain |
| `internal/breaker` | Circuit-breaker state machine |
| `internal/ratelimit` | Token-bucket per-key, override resolution |

**Conventions:**

- One `_test.go` per file under test (`prompt.go` ↔ `prompt_test.go`).
- Table-driven for any function with branching logic.
- Use `t.Run(name, …)` so each case shows up individually in CI output.
- Never sleep > 100ms; use injected clocks for time-dependent code.

```bash
# Run a single package
go test -race -count=1 ./internal/prompt/

# Run a single test
go test -race -run TestPromptDetector_BlocksJailbreak ./internal/prompt/
```

---

## 2. Integration Tests

Build-tag `//go:build integration`. These tests open real connections to
PostgreSQL and exercise the SQL written in `internal/db/*_store.go`.

### Setup

```bash
# Spin up a throwaway Postgres for tests
docker run -d --name vg-test-pg \
    -e POSTGRES_USER=vertguard -e POSTGRES_PASSWORD=vertguard \
    -e POSTGRES_DB=vertguard_test -p 5440:5432 \
    postgres:16-alpine

export VERTGUARD_TEST_DB_URL="postgres://vertguard:vertguard@127.0.0.1:5440/vertguard_test?sslmode=disable"

make test-integration
```

The test helper:

1. Connects with the supplied URL.
2. Applies every migration in `internal/db/migrations/` from scratch.
3. `TRUNCATE`s every mutable table between tests so they cannot leak.
4. Closes the pool on `t.Cleanup`.

### Coverage targets

| Store | Behaviours verified |
|-------|---------------------|
| `prompt_store` | Insert dedup, classification filter queries, scan history pagination |
| `phishing_store` | Same as prompt_store, plus `kind` filter |
| `identity_store` | `claim_hash` index used (EXPLAIN-style assertion) |
| `audit_store` | Append-only insert, time-bounded query, actor filter |
| `denylist_store` | UNIQUE constraint, GC of expired entries |
| `ratelimit_store` | Override resolution precedence (`sub` > `ip` > default) |

### Skip behaviour

Integration tests **skip cleanly** when `VERTGUARD_TEST_DB_URL` is not
set, so plain `go test ./...` stays fast on developer machines and in
unit-only CI lanes.

---

## 3. End-to-End Tests

Build-tag `//go:build e2e`. The most important test in the suite —
`TestE2E_FullScanFlow` — wires up the entire stack (HTTP server, JWT
middleware, CITADEL stub, ML model, Redis cache, threat-feed importer)
and exercises the same flow a real client uses:

1. POST `/api/v1/auth/token` with a bootstrap API key → JWT
2. POST `/api/v1/scan/prompt` with a known jailbreak payload → `BLOCKED`
3. Verify the scan row landed in `prompt_scans` with the right
   classification + ATLAS technique
4. Verify CITADEL stub received a WORM emit for the scan
5. Verify the outbound webhook fired with a valid HMAC signature

Run with:

```bash
export VERTGUARD_TEST_DB_URL="postgres://…"
export VERTGUARD_TEST_REDIS_URL="redis://127.0.0.1:6379/3"  # optional
make test-e2e
```

Tests under `tests/e2e/` are also runnable as Go programs against a
deployed instance — useful for production smoke tests after deploy.

---

## 4. ML Model Tests

Module-specific accuracy tests live under `python/tests/` and cover:

- Phishing — precision / recall on the held-out validation set
- Prompt-injection — false-positive rate on a corpus of legitimate prompts
- Identity — replay-attack detection rate

```bash
cd python
pytest tests/ -v
```

Model performance gates are wired into CI: a model whose validation
F1 score regresses by more than 2 percentage points fails the build.

See [ml-training-guide.md](ml-training-guide.md).

---

## 5. Fuzz Testing

Critical parsers run Go's native fuzzer:

```bash
go test -fuzz=FuzzPromptDetector -fuzztime=60s ./internal/prompt/
go test -fuzz=FuzzC2PAManifest -fuzztime=60s ./internal/media/
go test -fuzz=FuzzPhishingURL -fuzztime=60s ./internal/phishing/
```

Found inputs land in `testdata/fuzz/<test>/` and become permanent
regression cases automatically.

---

## 6. Performance / Benchmarks

```bash
make bench
```

Runs the benchmarks documented in [performance.md](performance.md)
covering prompt scan, phishing scan, HMAC signing, and ATLAS lookup.

---

## CI Pipeline

The CI lane runs in this order; a failure short-circuits the rest:

1. `go vet ./...`
2. `golangci-lint run`
3. `make test` (unit, with `-race`)
4. `make test-integration` (against a fresh Postgres in the runner)
5. `make test-e2e` (against full stack-on-runner)
6. Coverage upload — fails the build if total coverage drops below 70%.
7. Fuzz smoke (60s per fuzz target on PRs that touch the parser code).
8. ML accuracy gate (`pytest python/tests/`).

---

## Coverage Targets

| Package class | Target |
|---------------|--------|
| `internal/auth`, `internal/citadel`, `internal/ratelimit` | ≥ 85% |
| Module detectors (`prompt`, `phishing`, `identity`, `media`) | ≥ 80% |
| `internal/db/*_store.go` (via integration) | ≥ 75% |
| Other packages | ≥ 60% |

`make test-cover` prints both per-package and total coverage.

---

## See Also

- [performance.md](performance.md) — benchmark methodology
- [data-model.md](data-model.md) — schema covered by integration tests
- [false-positive-handling.md](false-positive-handling.md) — model
  performance gates and corpus management
- [troubleshooting.md](troubleshooting.md) — flaky-test diagnosis
