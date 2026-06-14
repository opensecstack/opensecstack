# OpenCSIRT Performance

> v1.0.0. Headline targets, hot paths, and load-testing methodology.
>
> **All numbers in this document are approximate.** They reflect
> design budgets, not measured benchmarks. Validate against your
> own deployment before relying on them for capacity planning. Real
> measurements land in v1.1 once the load harness is shipped.

---

## Methodology

The intended load-test harness drives the API with a mix of:

- 60% list reads (`GET /incidents`, `GET /advisories`,
  `GET /metrics/snapshot`)
- 25% incident writes (`POST /incidents`, `POST /incidents/{id}/close`)
- 10% advisory drafts (`POST /advisories` — exercises the Python
  subsystem)
- 5% advisory publishes (`POST /advisories/{id}/publish` — fans out
  to ThreatFlow + NIS2 + CITADEL)

against a Postgres warmed with 50 000 historical incidents and
5 000 advisories. The harness is not part of `make test`; it lives
under `tests/perf/` (TBD in v1.0.0; tracked on ROADMAP).

Numbers below are design targets sized for the workload above.

---

## Headline targets (approximate)

| Metric | Target | Notes |
|---|---|---|
| API p95 (`GET` endpoints) | < 200 ms | Postgres-bound; assumes warm cache and hot indexes. |
| API p95 (`POST` endpoints, no fan-out) | < 250 ms | Single Postgres txn (business row + outbox row). |
| API p99 (`GET`) | < 500 ms | Tail driven by occasional pgxpool waits at the `OPENCSIRT_DB_MAX_CONNS=16` ceiling. |
| Advisory draft latency | 1–5 s | Dominated by Python IOC enrichment (external APIs). See [Bottlenecks](#bottlenecks). |
| Advisory publish latency | < 1 s | No Python call; inserts outbox rows + side-effect dispatches. |
| CITADEL emit p95 (when reachable) | < 500 ms | Single signed POST per outbox row. |
| CITADEL outbox lag (p95) | < `OPENCSIRT_OUTBOX_TICK` × 2 = ~20 s | Default tick is 10 s. |
| IRFlow webhook ack | < 100 ms | Verify HMAC + insert one row + return. |
| Login endpoint | < 100 ms | sha256 + JWT mint, in-memory user table. |

Treat every threshold as a design target — flag deviations through
your monitoring rather than trusting these as SLOs.

---

## Postgres pool sizing

`OPENCSIRT_DB_MAX_CONNS` defaults to `16` per API replica. With 2
replicas (the Helm default), that is 32 simultaneous Postgres
connections from the API layer alone. A target of **100
concurrent CSIRT operators** is comfortably served, on the
assumption that:

- Operators spend most of their session on read-heavy dashboard
  views (cheap).
- Bulk write bursts (mass-close on incident remediation) come
  from at most a handful of operators at a time.

For deployments expecting > 100 concurrent operators or more than
4 API replicas, raise both `OPENCSIRT_DB_MAX_CONNS` and Postgres
`max_connections` together. Do not raise either in isolation.

---

## Hot paths

### Incident list (`GET /incidents`)

Index used: `idx_incidents_status_opened (status, opened_at DESC)`.
Pagination via `limit`/`offset`. Approximate at 50 k rows: < 30 ms
for a `(status='open' LIMIT 50)` scan, < 100 ms p95 with severity
filter (additional bitmap index hit on `idx_incidents_severity`).

### Metrics snapshot (`GET /metrics/snapshot`)

Several aggregate queries. The expensive ones:

- `SELECT severity, count(*) FROM incidents WHERE status IN ('open','triaged','contained') GROUP BY severity`
- `SELECT state, count(*) FROM citadel_outbox GROUP BY state`
- `SELECT min(created_at) FROM citadel_outbox WHERE state='pending'`

All three hit covering indexes. Approximate p95 < 80 ms at the
target row counts. Cache the snapshot at the API layer with a 5-
second TTL if your dashboard polls aggressively (not done by
default in v1.0.0).

### Outbox watcher

Runs on `OPENCSIRT_OUTBOX_TICK` (default `10s`). Each tick:

```sql
UPDATE citadel_outbox
SET state = 'sending'
WHERE id IN (
    SELECT id FROM citadel_outbox
    WHERE state = 'pending'
    ORDER BY created_at
    LIMIT 100
    FOR UPDATE SKIP LOCKED
)
RETURNING *;
```

`SKIP LOCKED` lets multiple API replicas share the queue without a
leader election. Batch size is 100; tune via the watcher
constructor if your peak emit rate exceeds 600 events/min.

---

## Bottlenecks

### Python advisory blocks on external APIs

The Python advisory subsystem performs IOC enrichment by calling
external APIs (VirusTotal, AlienVault OTX, abuse.ch URLhaus,
optionally MISP). Tail latency is dominated by:

- VirusTotal rate limit (4 req/min on the public free tier; paid
  tiers are higher but still bounded).
- OTX outage / 5xx — the subsystem retries with exponential backoff,
  which extends the draft latency budget.

Mitigations:

1. Operate a Redis cache for IOC enrichment responses (1 h TTL by
   default, 24 h for known-clean indicators).
2. Configure connector timeouts aggressively (5 s per connector,
   20 s total for the draft).
3. Run IOC enrichment **in parallel** across connectors. v1.0.0
   does this with `asyncio.gather`.

### Single-instance Python subsystem

v1.0.0 binds **one** Python advisory replica. Concurrent draft
requests serialise on the worker pool (`uvicorn` with 4 workers by
default). At ~5 s per draft, theoretical sustained throughput is
~48 drafts/min. National CSIRTs draft far below that ceiling
(typical: a handful of drafts per day), so this is not a problem
in practice — but it is a hard ceiling and must be respected.

Horizontal scaling is gated on stateless verification of the
Python container (no in-process caches that would diverge across
replicas) — tracked for v1.1.

### Postgres SPOF

OpenCSIRT does not multi-master. A Postgres outage stops all
writes; reads can degrade depending on your HA setup. Use a
managed Postgres or a Patroni-class HA cluster.

---

## Capacity planning

For a typical national CSIRT, approximate steady-state working
figures:

| Quantity | Approximate range |
|---|---|
| Incidents per year | 500 – 2 000 |
| Advisories per quarter | 50 – 200 |
| Constituencies | 100 – 500 |
| Concurrent operators | 5 – 50 (peaks during major events) |
| CITADEL events per day | 10 – 100 |
| ThreatFlow IOC pull volume | 1 000 – 10 000 indicators / pull, every 60 s |

These ranges are drawn from public reports (FIRST, ENISA national-
CSIRT capability surveys) and are illustrative only. Your numbers
will vary — flag them when sizing.

At the upper end of the table, the v1.0.0 schema and process
topology have substantial headroom — Postgres footprint is well
under 10 GB after a year, and the API runs comfortably on 2 small
replicas.

Sector CSIRTs (telecom, energy, finance) typically run at 10×
those volumes during peak events; plan for 4 API replicas, 32
DB connections, and a Redis cache in front of IOC enrichment.

---

## Limitations (v1.0.0)

- **No horizontal Python scaling.** Single advisory subsystem
  replica. See above.
- **No async advisory generation.** `POST /advisories` is
  synchronous — the operator's HTTP request blocks for the full
  draft latency. v1.1 will add a `pending_drafts` table and an
  async worker.
- **No load-test harness shipped.** The numbers in this document
  are design targets, not measurements. Tracked on ROADMAP.
- **No Postgres read-replica routing.** All reads go to the
  primary. With managed Postgres and a read replica, operators can
  point `OPENCSIRT_DB_URL_RO` (planned for v1.1) at the replica
  for the dashboard's read path.

---

## See also

- [architecture.md](architecture.md)
- [deployment.md](deployment.md)
- [data-model.md](data-model.md)
- [testing.md](testing.md)
