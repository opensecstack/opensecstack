# IRFlow Roadmap

Direction for IRFlow after the v1.0.0 release. Subject to revision as the
OpenSecStack ecosystem evolves.

## Completed (v1.0.0)

- Incident lifecycle (`open → investigating → contained → eradicating → recovering → closed`) with guarded transitions
- Actions + IOCs + timeline
- Playbook subsystem with graph-based executor, per-step timeouts, cycle protection
- Webhook ingestion from APIGuard, CITADEL, ThreatFlow (HMAC-SHA256 + replay window)
- CITADEL MARSHAL evaluation on action submission (REFUSE / HARD_STOP enforced)
- CITADEL WORM anchoring on incident creation
- NIS2 Compass Article 23 notification (async)
- JWT auth + role-based access control + structured audit log
- Prometheus metrics + `/metrics` endpoint
- Real-DB integration tests behind `integration` build tag

## v1.1 — Targeted hardening (next 6-8 weeks)

| Item | Description |
|---|---|
| Webhook deduplication | Persist seen `event_id`s in a small table with TTL; reject replays even with fresh signatures |
| WORM retry | Background worker that retries failed WORM emits with exponential backoff so nothing falls through the cracks |
| NIS2 notification retry | Same pattern as WORM retry — keep trying until the deadline window |
| Performance benchmarks | End-to-end latency numbers under realistic load; baseline for future regressions |
| OpenAPI 3 spec | Generated from handler metadata; serve at `/api/v1/openapi.json` |
| Production dashboard | Grafana JSON dashboards shipped with the repo (`deploy/grafana/`) |

## v1.2 — Automation & correlation (after v1.1)

| Item | Description |
|---|---|
| Playbook triggers | Automatically execute matching playbooks when a webhook arrives (event_type + severity match) |
| CEL evaluation | Real expression evaluation for `StepTypeConditional` (currently a dry-run stub) |
| Threat correlation | When a ThreatFlow bundle arrives without an `incident_id`, match against open incidents by `source_ref` or IOC overlap |
| APIGuard rescan step | Executor step calls APIGuard to re-scan a target and blocks on the result |
| IRFlow outbound webhooks | Notify other platforms on incident state changes |

## v2.0 — Post-MVP (exploratory)

| Item | Description |
|---|---|
| Multi-tenant isolation | `project_id` already plumbed everywhere; elevate to a first-class tenancy boundary with separate JWT audiences |
| Incident merging | Two incidents can be collapsed into one with full timeline preservation |
| SLA tracker | P1/P2 SLA countdown visible in the API and metrics; breach emits a webhook |
| Dashboard UI | A separate frontend project consuming the existing API — likely TypeScript + React, reusing the OpenSecStack design system |
| Auto-triage AI | Classification suggestions for untagged incoming events using embeddings against the historical corpus |

## Non-goals

- IRFlow will not become a ticketing system — no comments, chat, or
  SLA-driven on-call rotations. Integrate with a dedicated tool if that is
  needed.
- No built-in identity provider. JWT issuance is delegated to an external
  IdP; IRFlow only verifies signatures.
- No workflow builder GUI in core. Playbooks are YAML/JSON files
  authored outside the product.

## Call for feedback

Planning reviews are ongoing — open a GitHub issue with the label
`roadmap` to propose additions or reprioritisations.
