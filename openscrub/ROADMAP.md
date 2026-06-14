# OpenScrub Roadmap

> Per-platform roadmap. Aligned with the ecosystem-wide
> [../ROADMAP.md](../ROADMAP.md). Phase 2 deliverable.

## Phase summary

| Phase | Window | Outcome |
|---|---|---|
| **Phase 2 v0.1.0** | 2026-Q1 | XDP loader + Go API skeleton, single-CIDR static rules |
| **Phase 2 v1.0.0** | 2026-05-09 | Feature complete — IOC pull, dashboard, CITADEL evidence |
| **Phase 2.1** | 2026-Q3 | Multi-NIC, per-VRF rules, BGP flowspec announcer |
| **Phase 3** | 2027-Q1 | SecureLab integration — DDoS-rule validation harness |
| **Post-1.0** | rolling | Audit findings, performance tuning, eBPF CO-RE for older kernels |

## Phase 2 v1.0.0 deliverable table

| # | Deliverable | Owner | Status |
|:-:|---|---|:-:|
| 1 | XDP/eBPF data plane (C) — LPM blocklist + per-CIDR rate-limit | Agent A (data plane) | ✅ |
| 2 | Rust + Aya loader, Unix-socket control to Go API | Agent A (data plane) | ✅ |
| 3 | Go HTTP API on `:8087` — rules CRUD, mitigations, metrics | Agent B (Go API) | ✅ |
| 4 | PostgreSQL schema + migrations (rules, mitigations, audit) | Agent B (Go API) | ✅ |
| 5 | ThreatFlow IOC puller (15-minute default cadence) | Agent B (Go API) | ✅ |
| 6 | CITADEL `openscrub.mitigation` evidence emitter | Agent B (Go API) | ✅ |
| 7 | OpenAPI 3.1 contract `api/openapi.yaml` | Agent B (Go API) | ✅ |
| 8 | React + Vite + TS dashboard (rules, live miti, metrics) | This agent | ✅ |
| 9 | i18n shqip + anglisht | This agent | ✅ |
| 10 | docker-compose.yml + Helm chart | This agent | ✅ |
| 11 | docs/ — architecture, api, deployment, threat-model | This agent | ✅ |
| 12 | tests/integration/ — bash + Go end-to-end | This agent | ✅ |
| 13 | Ecosystem updates — ECOSYSTEM.md, deployment-topology.md | This agent | ✅ |

## Phase 2.1 (planned 2026-Q3)

- **Multi-NIC attach** — one loader, multiple `XDP_FLAGS_DRV_MODE` attaches.
- **Per-VRF rule sets** — separate blocklist maps per network namespace.
- **BGP flowspec announcer** — push verified rules upstream to a peer router.
- **Hardware offload (Mellanox/Intel)** — opt-in `XDP_FLAGS_HW_MODE` where supported.

## Phase 3 (planned 2027-Q1)

- **SecureLab harness** — replay recorded DDoS captures against a
  staging OpenScrub, assert drop/pass invariants per rule.
- **AUGUR feedback** — flag operators whose rule patterns drift from
  the cohort baseline (anomaly: huge `/8` blocks, IPv4 0.0.0.0/0).

## Out of scope

- L7 mitigation (HTTP flood, slowloris) — that belongs in a reverse-proxy WAF, not XDP.
- TLS termination, application firewalling, content inspection.
- Volumetric scrubbing past NIC line rate — handled by upstream BGP scrubbing partners.

## Related

- [../ROADMAP.md](../ROADMAP.md) — ecosystem-wide roadmap
- [../ECOSYSTEM.md](../ECOSYSTEM.md) — phase mapping
- [CHANGELOG.md](CHANGELOG.md) — what actually shipped
