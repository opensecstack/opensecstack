# VertGuard — Good First Issues

Seed issues for contributors joining VertGuard Phase 4.1. Each is
scoped to a day or less of focused work, has clear acceptance
criteria, and produces shippable value.

**How to use:** after scaffold commit lands in
`opensecstack/opensecstack`, create these as GitHub issues with the
`good-first-issue` + `vertguard` labels. Contributors claim via PR.

Generator command (run from repo root):

```bash
# Once issues are drafted, batch-create with:
gh issue create --repo opensecstack/opensecstack \
  --title "vertguard: <title>" \
  --body-file .github/issues/vg-<N>.md \
  --label good-first-issue,vertguard,phase-4.1
```

---

## VG-001 — Add OWASP LLM Top 10 pattern: instruction override (basic)

**Module:** 3 · **Lang:** Rust · **Estimate:** 2-4 hours

Implement the first pattern in `rust/prompt-patterns/src/owasp_llm.rs`:

- `LLM01.instruction_override.v1` — matches "ignore previous
  instructions" family of attacks
- Regex-based, case-insensitive
- Base confidence: 0.95
- Tag `atlas_technique`: `AML.T0051.000`
- Add 5+ positive test cases + 5+ false-positive test cases

**Acceptance:**
- `cargo test -p vertguard-prompt-patterns` passes
- Pattern visible via `Engine::scan()` on all positive cases
- No false positives on benign English text corpus in `tests/fp/prompt/technical_questions/`

**References:** [docs/module-3-prompt-injection.md](../docs/module-3-prompt-injection.md), [docs/owasp-llm-top10-coverage.md](../docs/owasp-llm-top10-coverage.md)

---

## VG-002 — Add DAN-family jailbreak patterns

**Module:** 3 · **Lang:** Rust · **Estimate:** 3-5 hours

Implement 3 DAN-style jailbreak patterns in
`rust/prompt-patterns/src/jailbreak.rs`:

- `LLM01.jailbreak.dan.v1` — classic "Do Anything Now" phrasing
- `LLM01.jailbreak.dan.v2` — developer-mode framings
- `LLM01.jailbreak.dan.v3` — "you are now DAN" persona takeover

Each with matching FP test cases (legitimate persona role-play).

**Acceptance:** tests pass; DAN variants detected; creative-writing
benign prompts do NOT match.

---

## VG-003 — Rust FFI surface for Go integration

**Module:** 3 · **Lang:** Rust + Go · **Estimate:** 4-6 hours

Wire the `ffi` feature in `rust/prompt-patterns`:

- Export `vg_scan(input_ptr, input_len, result_ptr)` C ABI function
- Marshal `ScanResult` through JSON for cross-language stability
- Add corresponding Go CGO wrapper in `internal/prompt/patterns_client.go`
- Build via `cargo build --features ffi`

**Acceptance:** Go test can call Rust scan engine and read results;
benchmark shows < 100 µs round-trip for 1 KB input.

---

## VG-004 — Health endpoint integration with Postgres

**Module:** core · **Lang:** Go · **Estimate:** 2-3 hours

Replace `stubPinger` in `cmd/server/main.go` with a real `pgxpool.Pool`-backed
Pinger:

- Create `internal/db/db.go` with `DB` struct wrapping pgxpool
- Implement `Ping(ctx) error` that runs `SELECT 1`
- Wire into `handlers.Health`
- `/health` returns `db: "ok"` when pool healthy, `db: "fail"` + 503 when not

**Acceptance:** `curl http://localhost:8091/api/v1/health` returns
valid response against running Postgres; returns 503 when Postgres
stopped.

---

## VG-005 — Initial SQL migration

**Module:** core · **Lang:** SQL · **Estimate:** 2-3 hours

Create `internal/db/migrations/001_initial.sql` with:

- `scans` table (scan metadata, no raw content)
- `patterns` table (active pattern-engine rules)
- `threat_iocs` table (AI-specific IOCs)
- `atlas_mappings` table (MITRE ATLAS technique mappings)
- `schema_migrations` table (migration bookkeeping)
- Indexes per `docs/architecture.md § Persistence`

Idempotent (`CREATE TABLE IF NOT EXISTS`).

**Acceptance:** `make migrate` runs cleanly; re-running is a no-op.

---

## VG-006 — MITRE ATLAS weekly sync worker skeleton

**Module:** 4 · **Lang:** Go · **Estimate:** 4-5 hours

Scaffold `internal/threatfeed/atlas.go`:

- Background worker that runs weekly per `threatfeed.atlas_sync_cron`
- Fetch from MITRE ATLAS API (mock endpoint initially)
- Parse + upsert into `atlas_mappings` table
- Metrics: `vertguard_threatfeed_atlas_last_sync_timestamp`

**Acceptance:** worker runs on schedule; DB populated with ATLAS
techniques; metrics exposed.

---

## VG-007 — `POST /api/v1/prompt/scan` real implementation

**Module:** 3 · **Lang:** Go · **Estimate:** 4-6 hours (after VG-003)

Replace `PromptScanTODO` with:

- Parse JSON request body
- Validate input size (≤ `prompt.max_input_size`)
- Call Rust pattern engine via FFI
- Apply scorer (aggregate matches, apply thresholds)
- Return structured response per `docs/api.md`

**Acceptance:** real scan happens; example from `docs/quick-start.md`
returns expected `BLOCKED` classification.

---

## VG-008 — JWT middleware (reused ecosystem pattern)

**Module:** core · **Lang:** Go · **Estimate:** 3-4 hours

Port IRFlow's JWT middleware to VertGuard:

- Copy pattern from `irflow/internal/auth/middleware.go`
- Adapt to VertGuard's config (`VERTGUARD_AUTH_SECRET`)
- Mount on `/api/v1/*` (not `/api/v1/health` or `/metrics`)
- Add `auth.dev_mode` bypass with WARN log

**Acceptance:** protected endpoints return 401 without token;
with valid token, pass through to handler.

---

## VG-009 — Prometheus metrics catalog

**Module:** core · **Lang:** Go · **Estimate:** 3-4 hours

Scaffold `internal/metrics/metrics.go` with Prometheus collectors:

- `vertguard_http_requests_total{method, path, status}`
- `vertguard_http_request_duration_seconds{path, quantile}`
- `vertguard_prompt_scans_total{classification}` (incremented when VG-007 lands)
- `vertguard_db_pool_connections{state}`

Wire `/metrics` endpoint (unauthenticated).

**Acceptance:** `curl /metrics | grep vertguard_` shows all series;
Prometheus scrape succeeds.

---

## VG-010 — React dashboard scaffold

**Module:** UI · **Lang:** React + TS · **Estimate:** 6-8 hours

Scaffold `web/` with:

- Vite + React 18 + TypeScript
- Three pages: Dashboard, Prompt Scanner, Threat Feed
- API client wrapping `fetch` with JWT auth
- Display status of VertGuard `/health` endpoint

**Acceptance:** `docker compose up dashboard` starts dashboard at
`:3009`; health status visible.

---

## VG-011 — C2PA trust store loader

**Module:** 1 · **Lang:** Rust · **Estimate:** 4-5 hours

In `rust/c2pa/src/lib.rs`:

- Implement `load_truststore(path: &str) -> Result<TrustStore>`
- Parse all `.pem` files in directory
- Validate each as X.509 certificate
- Return collection ready for `c2pa` crate consumption

**Acceptance:** tests pass; malformed PEM files cause init failure
with clear error.

---

## VG-012 — Docker image + multi-stage build

**Module:** core · **Lang:** Dockerfile · **Estimate:** 3-4 hours

Write `Dockerfile`:

- Multi-stage: Rust build → Go build → final runtime
- Non-root user
- Minimal base image (distroless or alpine)
- Size target: < 80 MB

**Acceptance:** `docker build .` succeeds;
`docker compose up -d` brings VertGuard + Postgres online;
`/health` responds in < 5 seconds of container start.

---

## VG-013 — GitHub Actions CI

**Module:** core · **Lang:** YAML · **Estimate:** 3-4 hours

`.github/workflows/ci.yml`:

- Go test matrix (Go 1.24)
- Rust test (`cargo test` + `cargo clippy`)
- golangci-lint
- Docker build verification
- Integration tests with Postgres service container

**Acceptance:** PR to main triggers CI; all jobs pass on clean branch.

---

## VG-014 — Makefile `test-fp` target wiring

**Module:** core · **Lang:** Go + Rust · **Estimate:** 2-3 hours

Scaffold `tests/fp/` structure matching `docs/false-positive-handling.md`:

- `tests/fp/prompt/creative_writing/`
- `tests/fp/prompt/technical_questions/`
- `tests/fp/prompt/edge_cases/`

Each directory has example text files + test harness that asserts
"no matches expected" on all inputs.

**Acceptance:** `make test-fp` runs and reports per-module FP rate;
baseline recorded as 0% on initial (empty) corpus.

---

## VG-015 — Evidence envelope schema + CITADEL client stub

**Module:** core · **Lang:** Go · **Estimate:** 4-5 hours

Scaffold `internal/citadel/connector.go`:

- Define `DetectionEvent` struct per `docs/citadel-integration.md`
- HMAC-SHA256 signer (reuse pattern from IRFlow)
- `Emit(ctx, event)` function targeting CITADEL `/api/v1/worm/emit`
- Local queue (bounded, in-memory) when CITADEL unreachable
- Metrics: `vertguard_worm_emit_total{event_type, result}`

**Acceptance:** unit tests pass with mock CITADEL; integration test
with live CITADEL staging emits successfully.

---

## Coordination

**Ordering tips:**

- VG-004, VG-005 are foundational — tackle early
- VG-001, VG-002 are Rust-only and parallel-safe
- VG-003 unblocks VG-007
- VG-010 can start independently of backend

**Claim etiquette:** comment on the issue with your timeline. If no
progress after 7 days, the issue re-opens for claim.

**Help:** `#vertguard-dev` on community Matrix / Slack (see
community/README.md).

## Related

- [CONTRIBUTING.md](../CONTRIBUTING.md)
- [docs/architecture.md](../docs/architecture.md)
- [docs/module-3-prompt-injection.md](../docs/module-3-prompt-injection.md)
- [docs/module-4-ai-threat-feed.md](../docs/module-4-ai-threat-feed.md)
- [../ROADMAP.md § Phase 4.1](../ROADMAP.md#phase-41--v010-2026-q4-target)
