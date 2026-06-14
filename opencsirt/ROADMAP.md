# OpenCSIRT Roadmap

> Per-platform roadmap. Aligned with the ecosystem-wide
> [../ROADMAP.md](../ROADMAP.md). Phase 3 deliverable.

## Phase summary

| Phase | Window | Outcome |
|---|---|---|
| **Phase 3 v0.1.0** | 2026-Q1 | Internal preview — Go API skeleton, constituency CRUD only |
| **Phase 3 v1.0.0** | 2026-05-10 | Feature complete — incidents, advisories, peer handshake, integrations |
| **Phase 3.1** | 2026-Q4 | MISP bridge, federated trust handshake v2, multi-language CSAF |
| **Phase 4** | 2027-Q2 | Automated CVD workflow, AUGUR-driven anomaly tagging on incident streams |
| **Post-1.0** | rolling | NIS2 reporting refinements, performance tuning, UI polish |

## Phase 3 v1.0.0 deliverable table

| # | Deliverable | Owner | Status |
|:-:|---|---|:-:|
| 1 | Go HTTP API on `:8088` — constituencies, incidents, advisories, peers, integrations | Agent A (Go core) | Done |
| 2 | PostgreSQL 16 schema + migration `0001_init` | Agent A (Go core) | Done |
| 3 | JWT auth with 6 roles (viewer, external_peer, analyst, operator, csirt_lead, admin) | Agent A (Go core) | Done |
| 4 | CITADEL outbox + watcher (`opencsirt.{incident,advisory,escalation}_*`) | Agent A (Go core) | Done |
| 5 | Python advisory subsystem on `:8089` — CSAF 2.0 generation + validation | Agent B (Python) | Done |
| 6 | NoopClient fallback path when advisory subsystem is unreachable | Agent B (Python) | Done |
| 7 | ThreatFlow IOC ingest puller | Agent A (Go core) | Done |
| 8 | IRFlow incident webhook (HMAC-SHA256, ±5-minute replay window) | Agent A (Go core) | Done |
| 9 | NIS2 Compass notifier (Article 23 push) | Agent A (Go core) | Done |
| 10 | VertGuard CVE subscriber | Agent A (Go core) | Done |
| 11 | OpenAPI 3.0 contract `api/openapi.yaml` | Agent A (Go core) | Done |
| 12 | React + Vite + TS dashboard (incidents, advisory editor, peer roster) | This agent | Done |
| 13 | docker-compose + Helm chart | This agent | Done |
| 14 | docs/ — architecture, api, deployment, integrations, peer handshake | This agent | Done |
| 15 | Prometheus metrics + JSON snapshot endpoint | Agent A (Go core) | Done |

## Phase 3.1 (planned 2026-Q4)

- **Federated trust handshake v2** — pairwise key pinning, automatic
  rotation, recovery from peer key loss without out-of-band channel.
- **MISP integration** — pull events from a MISP instance and surface
  them as IOC bundles attached to OpenCSIRT incidents; push selected
  CSAF advisories back as MISP events.
- **Multi-language CSAF localization** — render `note` blocks in
  multiple constituency languages from a single canonical source.
- **Automated CVD workflow** — coordinated vulnerability disclosure
  state machine (received → triaged → vendor-notified → embargoed →
  published) tied to advisory drafts.

## Phase 4 (planned 2027-Q2)

- **AUGUR-driven anomaly tagging** — flag incidents whose IOC pattern
  drifts from the cohort baseline.
- **Cross-CSIRT advisory diffing** — detect when two peer CSIRTs
  publish substantively different advisories for the same CVE.

## Out of scope (explicit non-goals)

- **Not a SIEM.** OpenCSIRT does not collect, parse, or correlate raw
  log streams. SIEM lives upstream of IRFlow.
- **Not a vulnerability scanner.** Vulnerability data flows in from
  VertGuard; OpenCSIRT consumes, does not discover.
- **Not a per-incident workflow engine.** That is IRFlow's job.
  OpenCSIRT pulls IRFlow incidents into a coordination layer; it
  does not replace IRFlow's case-management screens.
- **Not a ticket system.** Abuse-mailbox triage is intentionally
  minimal — enough to land a row in `incidents`, not a full helpdesk.

## Related

- [../ROADMAP.md](../ROADMAP.md) — ecosystem-wide roadmap
- [../ECOSYSTEM.md](../ECOSYSTEM.md) — phase mapping
- [CHANGELOG.md](CHANGELOG.md) — what actually shipped
- [README.md](README.md)
