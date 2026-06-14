---
status: Accepted
date: 2026-04-01
---
# ADR-003: Incident-to-advisory linking via incident_id foreign key

## Context
High-severity IRFlow incidents often result in an OpenCSIRT CSAF advisory. The link between an incident and its advisory must be traceable in both systems.

## Decision
OpenCSIRT advisory records carry an optional `incident_id` UUID field. When an operator drafts an advisory from an IRFlow incident, the incident UUID is set. IRFlow stores a reciprocal `advisory_id` on the incident once the advisory is published. Neither system owns the relationship — both carry the foreign key.

## Consequences
- No cross-service foreign key constraint (each DB is independent) — consistency is eventual
- Deleting an incident orphans the advisory's `incident_id` (acceptable; advisory is the primary record after publish)
- Enables cross-platform dashboards that join on the shared UUID
