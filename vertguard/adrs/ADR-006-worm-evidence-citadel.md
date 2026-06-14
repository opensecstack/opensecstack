## ADR-006 — All detection events emitted as WORM evidence to CITADEL

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.1
- Owners: VertGuard core, Compliance
- Related: [`docs/architecture.md`](../docs/architecture.md),
  [`internal/citadel/`](../internal/citadel/),
  ADR-008 (outbox pattern for CITADEL delivery)

## Context

VertGuard produces security detections (prompt injection, phishing,
deepfake media, synthetic identity, AI IOCs). These detections are
evidence for incident response and compliance reporting under NIS2
Article 21. Evidence must be tamper-proof: an attacker who also
compromises VertGuard must not be able to erase the detection record.

The OpenSecStack ecosystem provides CITADEL ARBITER, an append-only
evidence store with HMAC-chain integrity. Every other opensecstack
platform (APIGuard, IRFlow, OpenCSIRT) uses CITADEL for this purpose.

## Decision

Every VertGuard detection event at or above the configured confidence
threshold is emitted to **CITADEL ARBITER** as a WORM entry before
the HTTP response is returned to the caller. The WORM entry ID is
included in the API response (`worm_entry_id` field) so callers can
reference the evidence record.

Emission uses the `citadel.Client` from `internal/citadel/`, which
applies HMAC signing with key rotation support
(`CitadelConfig.HMACSecrets`). `CitadelConfig.DryRun=true` enables
development mode where emit calls are logged but no network request
is made.

## Reasons

- **Tamper-proof audit trail.** CITADEL's append-only store and
  HMAC integrity chain mean that a detection record cannot be
  deleted or modified after the fact, even by an operator with
  direct database access.
- **Ecosystem consistency.** All opensecstack platforms emit to
  CITADEL. Using the same pattern means IRFlow and OpenCSIRT can
  correlate VertGuard evidence with detections from other platforms
  without bespoke integration.
- **Compliance.** NIS2 Article 21(2)(e) requires that essential
  service operators maintain auditable records of security events.
  CITADEL WORM entries satisfy this requirement with a tamper-
  evident chain.
- **Emit-before-respond.** Returning the WORM entry ID in the API
  response gives callers a verifiable reference. Emitting after
  the response would allow an attacker to disrupt the connection
  between response and emit to create an untraceable detection.

## Consequences

- **CITADEL availability on hot path.** Emit happens before response.
  If CITADEL is unreachable and the async buffer is full, the
  handler blocks or returns an error. The async buffer
  (`CitadelConfig.AsyncBuffer`) decouples the emit from the response
  for typical transient failures; see ADR-008 for the outbox pattern
  that covers crash scenarios.
- **DryRun mode required for dev.** Running without a CITADEL
  endpoint in development must set `VERTGUARD_CITADEL_DRY_RUN=true`
  to avoid connection errors on every scan.
- **WORM entry ID in response.** API callers receive `worm_entry_id`
  in every positive detection response. Callers must treat this as
  an opaque reference — the ID format is CITADEL-internal.

## Alternatives considered + rejected

- **Local-only audit log.** Append-only log on disk is not tamper-
  proof against operators with file system access. **Rejected.**
- **PostgreSQL audit table.** Mutable rows; no HMAC chain; DB
  operator can delete rows. Retained as secondary persistence
  (`scans` table stores scan metadata) but not as the primary
  evidence record. **Rejected as primary.**
- **Emit after response.** Creates a window where the response
  exists but the evidence does not; exploitable by a sophisticated
  attacker. **Rejected.**

## Validation

- `go test ./internal/citadel/...` covers emit, HMAC signing, key
  rotation, DryRun mode, and async buffer behaviour.
- Integration test: `POST /api/v1/prompt/scan` with a BLOCKED input
  must return `worm_entry_id` in the response body.
- `VERTGUARD_CITADEL_DRY_RUN=true` must produce no network traffic
  to the CITADEL endpoint; log line `citadel dry-run` must appear.

## Follow-ups

- ADR-008 — transactional outbox pattern for crash-safe CITADEL
  delivery.
- Phase 4.3: CITADEL MARSHAL integration for auto-response gating
  on confirmed detections.
