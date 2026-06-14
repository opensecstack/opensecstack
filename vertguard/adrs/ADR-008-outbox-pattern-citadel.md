## ADR-008 — Transactional outbox pattern for CITADEL event delivery

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.1
- Owners: VertGuard core
- Related: [`docs/architecture.md`](../docs/architecture.md),
  ADR-006 (WORM evidence requirement),
  [`internal/citadel/`](../internal/citadel/),
  [`internal/db/`](../internal/db/)

## Context

ADR-006 requires that every detection event above threshold is emitted
to CITADEL ARBITER before the HTTP response is returned. A naive
implementation emits directly from the handler. But if the Go process
crashes after writing the detection to the `scans` table and before
the CITADEL emit completes, the evidence record is lost. This is the
dual-write problem: two systems (PostgreSQL and CITADEL) must both
record the event, but there is no distributed transaction spanning
both.

The same problem was solved in OpenCSIRT using the transactional
outbox pattern.

## Decision

VertGuard uses the **transactional outbox pattern** for CITADEL event
delivery:

1. The handler writes the scan result **and** an outbox row to
   PostgreSQL in the same database transaction. The outbox row
   carries the serialised CITADEL event payload and a `sent=false`
   flag.
2. A background goroutine (the "watcher") polls the outbox table,
   delivers pending events to CITADEL, and marks rows `sent=true`
   on acknowledgement.
3. On process restart, unsent outbox rows are delivered before
   accepting new traffic.

The `CitadelConfig.AsyncBuffer` controls the in-memory channel depth
for immediate (non-outbox) delivery. The outbox is the durability
backstop, not the primary path.

## Reasons

- **Atomicity without distributed transactions.** Writing to the
  outbox in the same transaction as the scan result means either
  both succeed or neither does. There is no window where the scan
  result exists but the CITADEL event does not.
- **Crash safety.** If the process crashes after the DB commit but
  before the CITADEL HTTP call, the outbox row survives in
  PostgreSQL. The watcher delivers it on the next startup.
- **Ecosystem consistency.** OpenCSIRT uses the identical pattern
  for its evidence chain. Operators familiar with OpenCSIRT
  runbooks can apply the same procedures to VertGuard.
- **No distributed transaction.** XA transactions across PostgreSQL
  and an HTTP API are not practical. The outbox pattern is the
  standard solution for this class of problem in Go services.

## Consequences

- **Outbox table required.** A `citadel_outbox` table (or equivalent
  within the existing schema) must exist in the PostgreSQL schema.
  Managed via the standard `schema_migrations` append-only migration
  sequence.
- **At-least-once delivery.** The watcher may deliver the same event
  twice if it crashes between CITADEL ack and marking `sent=true`.
  CITADEL must be idempotent on duplicate event IDs (it is, by
  design — event IDs are UUIDs generated at row-insert time).
- **Latency on crash path only.** The outbox watcher adds delivery
  latency only in the crash-recovery path. The normal path uses
  the async buffer (`AsyncBuffer`), which delivers in-process
  without a watcher round-trip.
- **No outbox without DB.** When `store` is nil (dev mode without
  PostgreSQL), the outbox is unavailable. Events are delivered
  in-memory only and lost on crash. Acceptable for dev; operators
  must use `VERTGUARD_DB_*` in production.

## Alternatives considered + rejected

- **Direct emit only (no outbox).** Simple but loses events on crash.
  Violates the tamper-proof evidence requirement from ADR-006.
  **Rejected.**
- **Kafka / message broker.** Adds a broker dependency. The existing
  PostgreSQL instance is sufficient for VertGuard's event volume.
  The broker adds ops cost with no benefit at current scale.
  **Rejected.**
- **Two-phase commit (XA).** Not supported by the CITADEL HTTP API.
  **Not applicable.**

## Validation

- `go test ./internal/citadel/...` must cover the outbox write,
  watcher delivery, and idempotent resend paths.
- Chaos test: kill the Go process immediately after a scan DB
  commit; restart; verify the CITADEL event is delivered and
  `worm_entry_id` is non-empty in the recovered scan row.

## Follow-ups

- Outbox retention policy: rows older than 30 days with `sent=true`
  can be pruned. Add a `VACUUM`-friendly archival job.
- Phase 4.3: explore CDC (change-data capture) via pgoutput as an
  alternative to polling, for reduced DB load at high scan volume.
