---
status: Accepted
date: 2026-04-01
---
# ADR-003: Transactional outbox on the emitter side

## Context
Platforms emit events to CITADEL as a side effect of state transitions (e.g. advisory published). A direct HTTP call inside the DB transaction risks: (a) the event being lost if CITADEL is down, or (b) the transaction rolling back after the event was already sent.

## Decision
Each platform that emits to CITADEL uses the transactional outbox pattern internally: the state change and the outbox row are written in the same DB transaction. A per-platform background sweeper delivers outbox events to CITADEL, retrying up to 3 times with exponential backoff, then dead-lettering. CITADEL itself is idempotent on duplicate event IDs (UUID dedup).

## Consequences
- At-least-once delivery — CITADEL may receive duplicates but deduplicates on `event_id`
- Platforms must each maintain an outbox table and sweeper (consistent pattern across the ecosystem)
- CITADEL availability is fully decoupled from platform availability
