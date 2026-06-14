---
status: Accepted
date: 2026-04-01
---
# ADR-001: Finite state machine for incident lifecycle

## Context
Incidents move through well-defined stages (open → triaged → contained → closed). Ad-hoc status updates risk skipping stages, losing audit trail, or applying wrong SLA timers.

## Decision
Implement the incident lifecycle as an explicit finite state machine. Valid transitions are enforced at the service layer:
- open → triaged (escalate)
- triaged → contained
- contained → closed (close)
- any → closed (emergency close, admin only)

Invalid transitions return 409 Conflict. Every transition emits a CITADEL evidence event.

## Consequences
- Audit trail is complete — no state can be skipped silently
- New states require a deliberate schema + code change (intentional friction)
- SLA timers are anchored to transition timestamps, not arbitrary updated_at
