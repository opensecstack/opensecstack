# CyberPath Performance Characteristics

> Status: design intent + budgets for v1.0.0 → v1.0.0. The numbers
> below are split into **published targets** (committed SLOs) and
> **to be measured** placeholders. Concrete benchmark numbers land
> here as `make bench` runs against the v1.0.0 alpha and v1.0.0
> stable builds. **No measured number is fabricated** — TBD entries
> will be filled in from real `make bench` output.

This document captures the SLOs CyberPath commits to, the capacity
model, the bottlenecks identified at design time, and the levers
operators have to tune them. Reproduction instructions are at the
bottom.

---

## SLOs (committed)

| Metric | Budget | Notes |
|---|---|---|
| API p95 latency (excluding sandbox start) | **< 100 ms** | All non-sandbox endpoints, including coverage queries and completion submission |
| Sandbox cold-start p95 | **< 5 s** | Wasmtime instance + capability bag + virtual FS staging. Docker labs (Module 3, v1.0.0) have a separate budget — see below. |
| Completion submission p95 | **< 200 ms** | Includes DB write of `completions` + outbox enqueue. Does *not* include CITADEL WORM submission (async, off the request path). |
| Coverage query p95 (`/api/v1/cyberpath/coverage/{user_id}`) | **< 150 ms** | NIS2 Compass calls this synchronously |
| Recommend query p95 (`/api/v1/cyberpath/recommend`) | **< 150 ms** | NIS2 Compass calls this synchronously |
| Web bundle size (initial load) | **< 500 KB gzipped** | The React shell + first lesson runner |

Docker-lab cold-start is intentionally larger (target p95 < 30s)
and is the primary motivator for the Wasm sandbox — see
[wasm-sandbox.md](wasm-sandbox.md) and ADR-012.

---

## Scan/request-path latencies (target — to be measured in v1.0.0)

| Endpoint | p50 target | p95 target | p99 target | Notes |
|---|---|---|---|---|
| `POST /api/v1/auth/token` | < 30 ms | < 80 ms | < 150 ms | Argon2id verify is the dominant cost |
| `GET /api/v1/tracks` | < 5 ms | < 20 ms | < 40 ms | LRU-cached, content-version-keyed |
| `GET /api/v1/lessons/{id}` | < 10 ms | < 30 ms | < 60 ms | LRU-cached |
| `POST /api/v1/lessons/{id}/complete` | < 80 ms | < 200 ms | < 350 ms | DB write + outbox enqueue |
| `POST /api/v1/labs/start` (Wasm) | < 2 s | < 5 s | < 8 s | Sandbox cold-start dominates |
| `POST /api/v1/labs/start` (Docker) | < 15 s | < 30 s | < 50 s | v1.0.0 only; mitigated by prewarm |
| `GET /api/v1/cyberpath/coverage/{user_id}` | < 50 ms | < 150 ms | < 250 ms | One JOIN-heavy query |
| `GET /api/v1/cyberpath/recommend` | < 30 ms | < 100 ms | < 180 ms | LRU-cached per `gap` |

All p95 figures are measured under the reference workload (1k mixed
RPS, 80% reads / 20% writes) on the reference benchmark host.

---

## Throughput (target — to be measured in v1.0.0)

| Workload | Target | Limiting factor |
|---|---|---|
| Lesson read (cached) | TBD; expected 8 000+ rps | LRU hit; serialise JSON |
| Completion submit | TBD; expected 800 rps | DB write + outbox enqueue |
| Coverage query | TBD; expected 600 rps | Aggregation join |
| Lab start (Wasm) | TBD; expected 50 starts/s | Sandbox host process |
| Lab start (Docker) | ~5 starts/s | Container spinup |
| Audit-event insert | TBD; expected 9 000+ rps | DB insert (no app logic) |

Horizontal scaling is linear up to the point where PostgreSQL
becomes the bottleneck — typically around 4–6 CyberPath replicas
hitting one DB. Past that, partition `completions` and
`lab_sessions` by year (see [migrations.md](migrations.md)) or
move audit-read traffic to read replicas.

---

## Capacity model

**Reference: 1000 concurrent learners on a 4-core 16 GB pod.**

A "concurrent learner" is one with an active session (token, page
loaded, possibly an in-flight lab). At 1000 concurrent learners the
expected steady-state load is:

| Resource | Steady-state |
|---|---|
| API requests | ~120 rps mixed |
| Active lab sessions | ~80 (8% of learners) |
| Active DB connections | 20–30 |
| RAM footprint (Go heap) | ~600 MB |
| RAM footprint (LRU caches) | ~200 MB |

**Sandbox spillover.** Lab sessions run in a dedicated sandbox
node-pool, separate from the API pod. The sandbox host crate
(`cyberpath-sandbox-host`) horizontally scales independently. Each
sandbox node holds the prewarm pool (default N=10 instances) plus
in-flight sessions; sizing is driven by *peak concurrent labs*, not
total enrolment. For 1000 concurrent learners with 8% lab
concurrency, expect ~100 concurrent Wasm sessions at peak; with
512 MB memory budget per session, that's ~50 GB across the pool —
plan for two 32-GB sandbox nodes minimum.

---

## Bottlenecks (design-time)

### Postgres connection pool under burst

When a cohort starts a lesson together (instructor-led training),
the API sees a burst of `POST /api/v1/lessons/{id}/start` requests.
Each request opens a connection from the pool to write the
`progress` row.

**Mitigation.** PgBouncer in transaction-pooling mode in front of
Postgres. Application-side connection limit is
`max_open_conns: 50` (vs Postgres's `max_connections: 200`); the
remaining headroom is for migrations + read replicas.

### Wasm cold-start memory allocation

A fresh wasmtime instance allocates its memory pages, runs the
module's `_start` initialiser, and stages the virtual FS. Cold
allocation is the dominant cost in the sub-second cold-start path.

**Mitigation.** Prewarm pool of N=10 sandbox instances per host.
The pool is replenished asynchronously after each acquisition.
Cold-start p95 with a warm pool is sub-second; without it, p95
climbs to 3–5 s. The pool size N=10 is tunable per deployment.

### CITADEL outbox drain on shutdown

If a CyberPath replica shuts down with un-drained outbox rows, the
events are picked up by the next replica's reconciliation pass.
For graceful shutdowns, the drain goroutine has a 10s budget to
flush.

**Mitigation.** Drain budget is a config knob. PreStop hook in the
Helm chart calls a drain endpoint before terminating the pod (lands
with v1.0.0).

### Coverage-query JOIN

The coverage endpoint joins `users → completions → lessons →
modules → tracks` and aggregates by NIS2 measure. Under burst it
can spike at p99.

**Mitigation.** Read-through cache on `(user_id, as_of_truncated)`
with a 60-second TTL; invalidated when a new completion lands for
the user. Cache hit ratio is expected to be high (>80%) because
NIS2 Compass typically queries the same user repeatedly during a
gap-analysis run.

---

## Microbenchmarks (target — to be measured in v1.0.0)

Reproduce via `make bench`:

```text
BenchmarkPathOrchestrator_Resolve            TBD ns/op   TBD B/op   TBD allocs/op
BenchmarkQuizScorer_Score                    TBD ns/op   TBD B/op   TBD allocs/op
BenchmarkContentVersionHash_BLAKE3_8KB       TBD ns/op   TBD B/op   TBD allocs/op
BenchmarkCertSign_Ed25519                    TBD ns/op   TBD B/op   TBD allocs/op
BenchmarkOutboxEnqueue                       TBD ns/op   TBD B/op   TBD allocs/op
BenchmarkSandboxColdStart                    TBD ns/op   TBD B/op   TBD allocs/op
BenchmarkSandboxColdStart_Prewarmed          TBD ns/op   TBD B/op   TBD allocs/op
BenchmarkCITADELHMACSign                     TBD ns/op   TBD B/op   TBD allocs/op
BenchmarkJWTVerify                           TBD ns/op   TBD B/op   TBD allocs/op
BenchmarkCoverageQuery                       TBD ns/op   TBD B/op   TBD allocs/op
```

Numbers are filled in from the v1.0.0 reference benchmark run; do
not edit by hand.

---

## Caching

CyberPath uses an in-memory LRU for content reads, keyed by
`content_version_id`:

| Cache | Key | TTL | Invalidation |
|---|---|---|---|
| Track LRU | `track_id` | indefinite | New `tracks` version inserted |
| Module LRU | `module_id` | indefinite | New `modules` version inserted |
| Lesson LRU | `(lesson_id, content_version_id)` | indefinite | Never (content versions are immutable) |
| Coverage LRU | `(user_id, as_of_minute)` | 60 s | New completion for user |
| Recommend LRU | `(gap, audience, max_duration)` | 5 min | Track-version bump |

The lesson LRU is the cheapest and the most beneficial: lesson
bodies are immutable per `content_version_id`, so the cache never
goes stale within the lifetime of an entry. Default cache size is
1000 entries (~50 MB at typical lesson size); tune via
`CYBERPATH_LESSON_CACHE_SIZE`.

---

## Web bundle size budget

| Asset class | Budget | Notes |
|---|---|---|
| Initial JS (gzip) | < 350 KB | React + router + i18n shell |
| Initial CSS (gzip) | < 50 KB | Tailwind purged |
| Initial HTML | < 10 KB | |
| Total initial load (gzip) | **< 500 KB** | Hard budget |
| Per-route lazy chunk | < 150 KB | Lesson runner, lab terminal, quiz UI lazy-loaded |
| xterm.js chunk | < 200 KB | Lazy-loaded only when a lab launches |

Bundle size is tracked in CI via `vite-bundle-visualizer`; a PR
that pushes the initial-load total over 500 KB fails the build.

---

## Mobile / low-bandwidth considerations

CyberPath is browser-first; the React app degrades cleanly on
slower connections.

- **Video lessons stream from CDN.** Lesson markdown can embed
  `<video>` tags; the runner detects 2G/3G connections (via
  `navigator.connection.effectiveType`) and shows a "switch to
  text-only" prompt that hides video and falls back to the
  transcript.
- **No video on quiz / lab pages.** Bandwidth-heavy assets are
  kept off the assessment path.
- **Service worker caches lesson bodies** (where the deployment's
  CSP permits SW). A learner who started a lesson online can finish
  it offline; completions queue locally and submit on reconnect.

---

## Reproducing benchmarks

```bash
# 1. Start the reference Postgres
docker run -d --name cp-bench-pg \
    -e POSTGRES_USER=cyberpath -e POSTGRES_PASSWORD=cyberpath \
    -e POSTGRES_DB=cyberpath_bench -p 5444:5432 \
    postgres:16-alpine

export CYBERPATH_TEST_DB_URL="postgres://cyberpath:cyberpath@127.0.0.1:5444/cyberpath_bench?sslmode=disable"

# 2. Apply migrations
make migrate-up

# 3. Run benchmarks
make bench

# 4. Run the full e2e load profile (wrk against the reference workload)
make load-test
```

The `make load-test` target lives in `tests/load/` and writes a CSV
+ flamegraph for the run. Compare against the published targets in
this document; a sustained > 20% regression on any p95 figure is a
release-blocker.

The reference benchmark host is the same hardware class VertGuard
uses (8 vCPU AMD EPYC, 16 GB RAM, local PostgreSQL 16). Numbers
captured on different hardware are informative but not directly
comparable to the published targets.

---

## v1.1+ items

- **Edge caching for content.** Lesson bodies + track manifests
  cached at a CDN edge with cache-busting on `content_version_id`.
  Reduces origin load for cohort-scale rollouts and improves
  global p95.
- **Lab pre-warm based on cohort schedule.** When a cohort has a
  lesson scheduled at 09:00 with a known lab, the sandbox host can
  prewarm the right lab images at 08:55. Avoids the first-learner
  cold-start tax.
- **Read replicas for coverage queries.** NIS2 Compass coverage
  reads are pure reads; routing them to a replica frees the primary
  for completion writes during cohort-scale activity.
- **Adaptive cache TTLs** based on content-version churn rate. A
  track that has had no new revision in months can have a longer
  TTL than a track in active authoring.

---

## See also

- [architecture.md](architecture.md) — request-path topology
- [wasm-sandbox.md](wasm-sandbox.md) — sandbox cold-start mechanics
- [data-model.md](data-model.md) — table layout + indexing
- [testing.md](testing.md) — perf regression in CI
- VertGuard reference: `vertguard/docs/performance.md`
