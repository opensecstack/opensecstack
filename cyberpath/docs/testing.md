# CyberPath Testing Guide

CyberPath ships a four-tier test pyramid: in-package **unit tests**
(Go + React), DB-backed **integration tests**, full-stack **e2e
tests** (Playwright + Go server + sandbox), and **content-quality
tests** (markdown + YAML + dead-link checking).

All tests run via `make`:

```bash
make test-unit          # Go + React unit (no live DB / sandbox)
make test-integration   # Go server + ephemeral Postgres + ephemeral Wasm host mock
make test-e2e           # Playwright on the React app + real Go server + sandbox
make test-content       # markdown linter + YAML schema + dead-link checker
make test-all           # everything above
```

---

## 1. Unit tests

### Go

Pure-Go tests with no external dependencies. Cover the per-package
business logic.

| Package | What it tests |
|---|---|
| `internal/path` | Track / module / lesson sequencing, prerequisite resolution |
| `internal/quiz` | Question-bank loading, randomisation determinism, scoring |
| `internal/lab` | Lab session orchestration (Wasm host calls mocked) |
| `internal/cert` | Ed25519 certificate signing + signature verification |
| `internal/citadel` | Outbox enqueue, HMAC signing, circuit breaker |
| `internal/coverage` | NIS2 Article 21 coverage calculation |
| `internal/content` | Content-version append-only enforcement, BLAKE3 canonicalisation |
| `internal/auth` | JWT issue/verify (via opensecstack/sdk), denylist enforcement |

**Conventions**

- One `_test.go` per file under test.
- **Table-driven** for any function with branching logic.
- `t.Run(name, …)` so each case shows up individually in CI output.
- Deterministic seeded fixtures — no random IDs. The seed is a
  package-level constant; tests that want randomness inject a
  seeded `*rand.Rand`.
- Never sleep > 100ms; use injected clocks for time-dependent code
  (matches the VertGuard pattern).

```bash
# Run a single Go package
go test -race -count=1 ./internal/path/

# Run a single test
go test -race -run TestPathOrchestrator_Prerequisites ./internal/path/
```

### React

| Test class | Scope |
|---|---|
| Component tests | Vitest + React Testing Library; one `*.test.tsx` per component |
| Hook tests | `useLessonProgress`, `useLabSession`, `useQuizScoring` |
| Business logic | Pure TS modules under `src/lib/` |

The focus is hooks + business logic; pure-presentational components
are not exhaustively covered (matches the project's "no hard
target" stance for React coverage).

```bash
cd web && npm test           # one-shot
cd web && npm run test:watch # watch
```

---

## 2. Integration tests

Build-tag `//go:build integration`. The runner spins up an
**ephemeral Postgres** (via `dockertest` or a CI service container)
and an **ephemeral Wasm host mock** that records calls instead of
actually instantiating modules. Integration tests exercise the SQL
in `internal/db/*_store.go` and the IPC contract between the API
and the sandbox host.

### Setup

```bash
# Spin up a throwaway Postgres for tests
docker run -d --name cp-test-pg \
    -e POSTGRES_USER=cyberpath -e POSTGRES_PASSWORD=cyberpath \
    -e POSTGRES_DB=cyberpath_test -p 5443:5432 \
    postgres:16-alpine

export CYBERPATH_TEST_DB_URL="postgres://cyberpath:cyberpath@127.0.0.1:5443/cyberpath_test?sslmode=disable"

make test-integration
```

The test helper:

1. Connects with the supplied URL.
2. Applies every migration in `internal/db/migrations/` from scratch.
3. `TRUNCATE`s every mutable table between tests so they cannot leak.
   `completions`, `content_versions`, `certifications`,
   `audit_events`, and `outbox` are NOT truncated mid-test —
   audit-chain tables are tested with their full append history.
4. Closes the pool on `t.Cleanup`.

### Coverage targets per store

| Store | Behaviours verified |
|---|---|
| `users_store` | INSERT, UNIQUE `(tenant_id, lower(email))`, soft-delete |
| `tracks_store` | GIN index on `nis2_measures` used for coverage queries |
| `content_store` | Append-only enforcement (UPDATE rejected at app layer) |
| `progress_store` | Upsert on `(user_id, lesson_id)`, GC of stale rows |
| `completions_store` | Append, FK to `content_version_id`, no DELETE path |
| `outbox_store` | Enqueue, claim-for-send, mark-sent, reconciliation sweep |
| `audit_store` | Append-only, time-bounded query, actor filter |

### Skip behaviour

Integration tests skip cleanly when `CYBERPATH_TEST_DB_URL` is not
set. Plain `go test ./...` stays fast on developer machines and in
unit-only CI lanes.

### Sandbox in integration tests

Integration tests use a **host-side mock** of the Wasm sandbox
(`internal/lab/sandboxmock`). The mock records every call and
returns scripted responses. Real wasmtime instantiation does not
run on every PR — it would slow the CI lane materially. Real Wasm
runs **nightly** via `make test-sandbox-real`, which exercises:

- module load + cosign verification against a corpus of test labs
- capability-bag enforcement (deny-by-default)
- resource-limit enforcement (memory, fuel, wallclock)
- audit-trail emission shape

Nightly failures open a tracking issue; PR-blocking would be
disproportionate to the change rate of the host crate.

---

## 3. End-to-end tests

Playwright on the React app, against a live Go server with a real
ephemeral Postgres and a real Wasm sandbox host (not the mock).

```bash
export CYBERPATH_TEST_DB_URL="postgres://..."
export CYBERPATH_TEST_SANDBOX_REAL=1
make test-e2e
```

The most important e2e test — `e2e/full-flow.spec.ts` — wires the
full stack and exercises a learner journey:

1. Register + log in via the React app
2. Start the canonical "Phishing recognition" track
3. Complete lesson 1 (text), assert `progress` row updated
4. Run lesson 2 lab (real Wasm sandbox), assert `lab_sessions` row +
   audit log entries
5. Take lesson 3 quiz, assert pass + `completions` row +
   `outbox` row enqueued
6. Verify the outbox-drain goroutine submits to the CITADEL stub
7. Check the CITADEL stub received the event with the expected
   `evidence_hash` + `content_version_id`

The "Phishing recognition" track is checked into
`testdata/tracks/phishing-recognition/` as the canonical e2e
fixture. It is the same content the v1.0.0 ships, frozen at the
test-fixture revision so test runs are reproducible.

Playwright traces are saved on failure for debug.

---

## 4. Content-quality tests

Track content (markdown + YAML) ships in the same repo as the code.
The content-quality lane catches authoring errors before they reach
production.

```bash
make test-content
```

Behind the target:

| Tool | Scope |
|---|---|
| `markdownlint-cli2` | All `*.sq.md` + `*.en.md` lesson files |
| `ajv-cli` | YAML schema validation for `track.yaml`, `lab.yaml`, quiz banks |
| `lychee` | Dead-link checker for outbound URLs in lesson markdown |
| custom Go validator | Cross-references: every `lesson.has_quiz` → quiz exists, every `lesson.has_lab` → lab manifest exists |

YAML schemas live in `schemas/` and are version-controlled. The
schema is the contract; lab + track authors validate locally
before opening a PR.

```bash
# Validate a single lab manifest
ajv validate -s schemas/lab.schema.json -d labs/phish-classify-1/lab.yaml
```

---

## 5. Performance regression

Two perf benchmarks run on every PR (not the full benchmark suite —
only the regression-sensitive ones):

```bash
go test -bench=BenchmarkSandboxColdStart -benchtime=10s ./internal/lab/
go test -bench=BenchmarkCompletionSubmit -benchtime=10s ./internal/path/
```

Numbers are compared against a baseline JSON checked into
`testdata/perf-baseline.json`. A regression > 20% fails the PR;
between 10% and 20% emits a warning. Baseline updates require a
named-reviewer approval.

The full benchmark suite (`make bench`) runs nightly. See
[performance.md](performance.md) for the full benchmark catalogue
and the published target numbers.

---

## 6. Coverage targets

| Package class | Target |
|---|---|
| `internal/auth`, `internal/citadel`, `internal/cert` | ≥ 85% |
| Module engines (`path`, `quiz`, `lab`, `coverage`, `content`) | ≥ 80% |
| `internal/db/*_store.go` (via integration) | ≥ 75% |
| Other Go packages | ≥ 60% |
| Overall Go coverage gate | **≥ 70%** (matches VertGuard) |
| React | no hard target; focus on hooks + `src/lib/` |

`make test-cover` prints both per-package and total coverage.

---

## CI pipeline

The CI lane runs in this order; a failure short-circuits the rest:

1. `go vet ./...`
2. `golangci-lint run`
3. `make test-unit` (Go + React, with `-race` on Go)
4. `make test-integration` (against a fresh Postgres in the runner)
5. `make test-content`
6. `make test-e2e` (full stack on runner; sandbox mock by default,
   real sandbox nightly)
7. Coverage upload — fails the build if total Go coverage < 70%
8. PR-scope perf benchmarks — fails on > 20% regression

---

## Tooling cheatsheet

```bash
make test-unit          # fast: Go unit + React unit
make test-integration   # needs CYBERPATH_TEST_DB_URL
make test-e2e           # needs Postgres + sandbox host (or mock)
make test-content       # markdown + YAML + dead-link
make test-sandbox-real  # nightly; runs real wasmtime
make test-cover         # coverage report
make test-all           # everything sequentially
make bench              # full benchmark suite (slow)
```

---

## See also

- [performance.md](performance.md) — benchmark catalogue and budgets
- [data-model.md](data-model.md) — schema covered by integration tests
- [wasm-sandbox.md](wasm-sandbox.md) — sandbox mock vs real
- [migrations.md](migrations.md) — migration testing
- VertGuard reference: `vertguard/docs/testing.md`
