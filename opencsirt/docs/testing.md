# OpenCSIRT Testing Guide

> v1.0.0. Three test tiers, one per layer in the tree.

OpenCSIRT ships three test tiers:

1. **Unit tests** — Go (`go test ./...`) and Python (`pytest`),
   no DB or peer needed.
2. **Integration tests** — Go contract tests behind the
   `//go:build integration` tag, requiring a real Postgres.
3. **End-to-end smoke** — `bash tests/integration/run.sh` driving
   the docker-compose stack.

The Makefile entry points are deliberately small (see
[`Makefile`](../Makefile)):

```bash
make test              # go test ./... + pytest + npm test
make test-integration  # bash tests/integration/run.sh
make lint              # go vet + ruff + black --check + eslint
make sec               # gosec + govulncheck + pip-audit
```

See [performance.md](performance.md) for load-testing methodology
(not run as part of the standard test matrix).

---

## 1. Unit tests

### Go

`go test ./...` covers the control-plane packages. Conventions
follow the wider [opensecstack](../../README.md) codebase: table-
driven tests, deterministic seeded fixtures, no sleeps over 100 ms,
injected clocks for time-dependent code.

Test packages currently in the tree:

| Package | What it covers |
|---|---|
| [`internal/auth`](../internal/auth/) | role rank ordering, JWT verify with rotation secrets, login hash equality, middleware reject paths |
| [`internal/constituency`](../internal/constituency/) | ISO-3166 country validation, NIS2 status enum, FK preservation on retire |
| [`internal/advisory`](../internal/advisory/) | CSAF-id format, TLP enforcement on read for `external_peer`, draft → publish → withdraw state transitions, idempotent publish |
| [`internal/integrations`](../internal/integrations/) | IRFlow HMAC verification (positive + negative), ThreatFlow puller dedup against `ioc_ingest_log`, NIS2 push dispatch, VertGuard handshake |

Run with the race detector:

```bash
go test -race ./...
```

Run a single package or test:

```bash
go test -race -count=1 ./internal/advisory/
go test -race -run TestPublishIsIdempotent ./internal/advisory/
```

Coverage target: **≥ 70%** on the four core packages above.
Coverage report:

```bash
go test -coverprofile=cover.out ./...
go tool cover -html=cover.out
```

### Python

The advisory subsystem ships a `pytest` suite under `python/tests/`.
Conventions:

- One test module per CSAF generator stage (header, vulnerabilities,
  product tree, IOC enrichment).
- IOC enrichment connectors are mocked via `responses` /
  `respx` — no live VirusTotal / OTX calls in unit tests.
- Schema validation runs against the upstream CSAF 2.0 JSON Schema
  on every generated document.

Coverage target: **≥ 80%** for the advisory subsystem (it is the
load-bearing piece of the Python tier).

```bash
cd python && python -m pytest --cov=opencsirt_advisory --cov-report=html
```

### React

`cd web && npm test` runs the Vitest suite over the dashboard
components. Coverage is informational rather than a CI gate in
v1.0.0.

---

## 2. Integration tests (Go)

Files behind the `//go:build integration` tag. They require a real
Postgres, addressed by `OPENCSIRT_DB_URL` (the same env var the
server reads). The harness in `tests/integration/` boots a
`postgres:16-alpine` container, applies migrations, and runs:

```bash
go test -tags=integration -count=1 ./internal/db/...
```

Covered:

- Each store's CRUD round trip.
- The `ON DELETE SET NULL` paths on `incidents.constituency_id` and
  `advisories.incident_id` (verifies evidence preservation).
- The CITADEL outbox state machine — insert, claim with
  `FOR UPDATE SKIP LOCKED`, transition to `sent` / `failed`.
- The `csaf_id` `UNIQUE` constraint surfacing as `409` at the API
  layer.

---

## 3. End-to-end smoke

`bash tests/integration/run.sh` does:

1. `make compose-up`
2. `migrate up`
3. Runs a sequence of `curl` calls (login, create constituency,
   open incident via IRFlow webhook with valid HMAC, draft
   advisory, publish, observe CITADEL outbox drain in dry-run
   mode).
4. Tears the stack down.

Run before every release. Not part of `make test` because it boots
containers — opt in via `make test-integration`.

---

## CI matrix expectations

The recommended CI matrix:

| Job | Trigger | Runtime |
|---|---|---|
| `lint` | every PR | < 1 min |
| `test` | every PR | < 3 min |
| `sec` | every PR | < 5 min |
| `test-integration` | every PR (or merge queue) | < 10 min |
| `e2e-smoke` | nightly + release tag | < 15 min |

`gosec`, `govulncheck`, and `pip-audit` are wired through `make
sec`. Findings at severity ≥ medium block the PR.

---

## Gaps tracked for v1.1

- **Fuzz harness.** No `go test -fuzz` corpus today. The IRFlow
  webhook parser, the CSAF JSON validator, and the JWT claim
  parser are the natural fuzz targets. Tracked on ROADMAP.
- **Property-based tests** (Hypothesis on the Python side) for
  CSAF document round-trips.
- **Mutation testing** on the auth / outbox state machines.

---

## See also

- [`Makefile`](../Makefile)
- [performance.md](performance.md)
- [migrations.md](migrations.md)
