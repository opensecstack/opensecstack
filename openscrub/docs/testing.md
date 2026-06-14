# OpenScrub Testing Guide

OpenScrub ships three test tiers, one per language in the tree:

1. **Unit tests** — Go, Rust, and React, no kernel or DB needed.
2. **Integration tests** — Go contract tests against a running
   stack (build-tag `integration`) and a `bash` harness that
   drives the docker-compose stack end-to-end.
3. **Live-kernel tests** — Rust tests gated behind
   `cargo test -- --ignored`, requiring `CAP_BPF` (or root) on a
   Linux host.

The Makefile entry points are deliberately small:

```bash
make test              # Go + Rust + web unit tests
make test-integration  # bash tests/integration/run.sh
make lint              # go vet + cargo clippy + npm lint
```

See [performance.md](performance.md) for load-testing methodology
(not run as part of the standard test matrix).

---

## 1. Unit tests

### Go

`go test ./...` covers the control-plane packages. Conventions
follow the wider `opensecstack` codebase: table-driven tests,
deterministic seeded fixtures, no sleeps over 100 ms, injected
clocks for time-dependent code (`Service.now` in
[`internal/rules/service.go`](../internal/rules/service.go) is the
canonical pattern).

| Package | What it covers |
|---|---|
| `internal/rules` | `CreateRequest.Validate`, `Service.Create/Delete/SweepExpired` against an in-memory repo and a fake dataplane.Client |
| `internal/db` | Per-store SQL via tagged tests (see Integration below) |
| `internal/citadel` | Event envelope construction, HMAC signing, retry behaviour |
| `internal/dataplane` | The Go-side `dataplane.Client` interface and its FFI / RPC adapters |
| `internal/metrics` | Prometheus collector wiring |
| `internal/ioc` | ThreatFlow puller logic |

```bash
# All Go unit tests with race detector
go test -race ./...

# One package
go test -race -count=1 ./internal/rules/

# One test
go test -race -run TestServiceCreate_RollsBackOnPlaneError ./internal/rules/
```

### Rust

`cargo test` covers the dataplane userspace library and the loader
binary, both inside the same crate at [`rust/dataplane/`](../rust/dataplane/)
(library + `[[bin]] openscrub-loader`). The crate runs cross-platform:
on non-Linux hosts the `Loader` resolves to a stub
([`loader_stub.rs`](../rust/dataplane/src/loader_stub.rs)) so unit
tests exercise the [`MapWriter`](../rust/dataplane/src/maps.rs)
surface against the in-memory shadow without needing a kernel.

```bash
# All Rust unit tests on the current host
cd rust/dataplane && cargo test

# Live-kernel tests — Linux only, require CAP_BPF
cd rust/dataplane && cargo test -- --ignored
```

`#[ignore]` is the convention for tests that need a real kernel:
attaching to a veth, populating live BPF maps, reading
`PERCPU_ARRAY` counters across CPUs. They run nightly on a Linux
runner, not on every PR.

### React

`npm test` runs the web dashboard's component and hook tests via
Vitest + React Testing Library (matches the `cyberpath` /
`apiguard` pattern). Coverage focus is hooks and `src/lib/`
modules; pure-presentational components are not exhaustively
covered.

```bash
cd web && npm ci && npm test
```

---

## 2. Integration tests

Two harnesses live under
[`tests/integration/`](../tests/integration/).

### Shell harness — `run.sh`

[`tests/integration/run.sh`](../tests/integration/run.sh) brings
up the full docker-compose stack
([`deploy/docker-compose.yml`](../deploy/docker-compose.yml)),
authenticates against the API, creates a blocklist rule, fires
~100 packets via `hping3` (or the dev-mode synthetic injector if
explicitly opted in via `OPENSCRUB_DEV_MODE=1`), and asserts:

1. The `pps_dropped` counter on `/api/v1/metrics` strictly
   increased.
2. A `mitigations` row exists for the spoofed source IP.

```bash
make test-integration
# or directly:
bash tests/integration/run.sh
```

Requires `docker`, `curl`, `jq`, and `hping3` (with `sudo`) on the
host. The harness tears down the compose stack on exit unless
`KEEP_STACK=1` is set.

> **Synthetic injector (`POST /api/v1/_test/inject`).** When `hping3`
> is unavailable on the runner, `run.sh` falls back to a debug-only
> HTTP injector at `/api/v1/_test/inject` — but **only** when
> `OPENSCRUB_DEV_MODE=1` is exported, so the harness never probes a
> debug surface against a prod deployment. The route is intended to
> be registered behind the `DevMode` gate in
> [`internal/api/server.go`](../internal/api/server.go); as of v1.0.0
> the gated registration has not landed, so the fallback branch only
> succeeds against a dev build that explicitly wires it. Tracked as a
> v1.0 hardening follow-up. Do **not** add this route to a production
> build, and do **not** document it on the public API surface
> ([api.md](api.md)).

The harness is intentionally **end-to-end**: it exercises the
PostgreSQL schema, the Go API, the Rust loader, the BPF program,
and the React-served metrics surface. It does not measure
throughput — see [performance.md](performance.md) for that.

### Go contract tests — `api_contract_test.go`

[`tests/integration/api_contract_test.go`](../tests/integration/api_contract_test.go)
is gated behind the `//go:build integration` tag. It expects a
running stack (typically the one `run.sh` brings up) and tests
the HTTP API contract directly:

- Rule create / get / delete lifecycle
- Validation refusals (e.g. dangerous CIDRs, ratelimit without
  PPS)
- `/api/v1/health` shape
- `/api/v1/metrics` shape

```bash
# stack must already be up at $OPENSCRUB_API_BASE
go test -tags=integration ./tests/integration/...
```

`OPENSCRUB_API_BASE` defaults to `http://localhost:8087`. See
[`tests/integration/README.md`](../tests/integration/README.md) for
the env-var matrix.

### DB-store integration

The `internal/db/*_store.go` files use real PostgreSQL semantics
(GIST CIDR indexes, INET / CIDR types, `RETURNING`, unique-
violation translation). The store tests run against an ephemeral
PostgreSQL spun up by the integration harness. The convention
mirrors VertGuard's: the test connects with
`$OPENSCRUB_TEST_DB_URL`, applies every migration in
[`migrations/`](../migrations/) from scratch, `TRUNCATE`s the
mutable tables between tests, and closes the pool on `t.Cleanup`.

If `OPENSCRUB_TEST_DB_URL` is unset, store tests **skip cleanly**
so plain `go test ./...` stays fast on developer machines.

---

## 3. Coverage targets

| Surface | Target | Rationale |
|---|---|---|
| `internal/rules`, `internal/citadel` | ≥ 85 % | Audit-load-bearing logic; every transition must have a test. |
| `internal/db/*_store.go` (via integration) | ≥ 75 % | SQL is data-driven; cover the UNIQUE / CHECK / FK paths. |
| Other Go packages | ≥ 60 % | Glue and config. |
| Overall Go gate | **≥ 70 %** | Matches the `opensecstack` standard. |
| Rust `rust/dataplane` (unit) | ≥ 70 % | The detached `MapWriter` shadow is fully exercisable without a kernel. |
| Rust live-kernel `--ignored` | not gated | Best-effort; nightly. |
| React | no hard target | Focus on hooks + `src/lib/`. |

`go test -cover ./...` for Go; `cargo tarpaulin` (or
`cargo llvm-cov`) for Rust on Linux runners.

---

## 4. Fuzzing

OpenScrub does not yet ship a `go fuzz` corpus. The high-value
fuzz targets — when authored — are:

- `rules.CreateRequest.Validate` — the JSON surface of
  `POST /api/v1/rules`. Many CHECK constraints; want to ensure no
  combination produces an in-memory rule the data plane rejects.
- `rules.ParseCIDR` — round-trip with arbitrary bytes; verify
  panics never escape and the returned prefix is `Masked`.
- The CITADEL event canonicalisation — fuzz against schema
  validation to ensure no odd inputs produce non-conforming JSON.

This is tracked as a v1.1 deliverable; absence of fuzz coverage in
v1.0.0 is a known gap.

---

## 5. Load testing

Load testing is **separate** from the test matrix above and is
documented in [performance.md](performance.md). The standard CI
lane does not generate line-rate traffic; that requires a paired
sender host and pktgen, which lives outside the per-PR runners.

A future `tests/perf/` harness will codify the pktgen procedure
(see [performance.md](performance.md#reproducing-benchmarks)).

---

## 6. CI matrix expectations

Per PR, the lane runs in this order; failure short-circuits the
rest:

1. `make lint` — `go vet`, `cargo clippy -- -D warnings`,
   `npm run lint`.
2. `make test` — Go + Rust (cross-platform unit) + web unit.
3. `make test-integration` — full docker-compose stack on a
   Linux runner with privileged mode (BPF needs it).
4. Coverage upload — fails the build if Go coverage < 70 %.

Nightly, additionally:

- Rust `cargo test -- --ignored` on a Linux runner with
  `CAP_BPF`.
- The pktgen perf harness (when it lands), comparing against the
  baseline numbers in [performance.md](performance.md).

The lint and unit lanes run on Linux **and** Windows runners (the
data-plane crate has a Windows-compatible stub loader so it
compiles cleanly on the dev host); the integration and ignored
lanes run on Linux only.

---

## See also

- [performance.md](performance.md) — load testing and benchmarks
- [data-model.md](data-model.md) — schema covered by integration tests
- [migrations.md](migrations.md) — migration testing in the harness
- [architecture.md](architecture.md) — what each layer does
