---
status: Accepted
date: 2026-05-01
---
# ADR-002: TLP as the advisory access control axis

## Context
Advisories carry sensitivity levels. Role-based access alone is insufficient — an operator role should see TLP:CLEAR and TLP:GREEN but not TLP:AMBER or TLP:RED without explicit clearance.

## Decision
TLP (Traffic Light Protocol) is enforced at the API layer as a second access control axis, independent of JWT role:
- TLP:CLEAR, TLP:GREEN — accessible to all authenticated roles
- TLP:AMBER, TLP:RED — blocked for `analyst` role; accessible to `operator` and above

The enforcement is in the advisory handler, not the DB query, so the DB always returns the full record and the handler gates on `(role, tlp)`.

## Consequences
- Simple to reason about: two axes (role rank, TLP level) independently enforced
- TLP:RED advisories are never exposed to analysts even if they somehow obtain the UUID
- Future: per-constituency TLP override (e.g. a constituency operator seeing their own TLP:AMBER) deferred to v0.2
