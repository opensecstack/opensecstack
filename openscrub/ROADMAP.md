# OpenScrub Roadmap

> Per-platform roadmap. Aligned with the ecosystem-wide
> [../ROADMAP.md](../ROADMAP.md). Phase 2 deliverable.

## Phase summary

| Phase | Window | Outcome |
|---|---|---|
| **Phase 2 v0.1.0** | 2026-Q1 | XDP loader + Go API skeleton, single-CIDR static rules |
| **Phase 2 v1.0.0** | 2026-05-09 | Feature complete — IOC pull, dashboard, CITADEL evidence |
| **Phase 2.1** | 2026-Q3 | Multi-NIC, per-VRF rules, BGP flowspec announcer |
| **Phase 2.2** | 2026-Q4 | Detection bot — observe-only scoring engine, gated auto-rules, chat-ops |
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

## Phase 2.2 (planned 2026-Q4)

Turns `docs/detection-thresholds.md` from an aspirational design doc into
`internal/detection/`, modeled on the layered classify → score → persist →
act pipeline reviewed in the FloodGate architecture reference, but scoped
to what OpenScrub can actually execute today (no RTBH until the Phase 2.1
flowspec announcer lands, and no action is ever taken off a single sample).

- **Observe-only scoring engine** — `internal/detection/`: per-prefix
  PPS/BPS/protocol-mix counters from XDP telemetry (+ FastNetMon alerts,
  ADR-003) evaluated on a fixed tick; verdict requires 2+ consecutive
  breaches before even logging `suspect`, never fires off one sample.
  Ships disabled-by-default (`detection.mode: observe`) so it can run
  against live traffic for a real baseline before anything auto-acts.
- **Config-driven thresholds, not hardcoded ones** — every threshold,
  trusted-prefix override, and hit-count in `openscrub.yaml` must be the
  value the engine actually reads; add a test that loads the shipped
  config and asserts the effective thresholds match it.
- **Gated auto-rules** — once baselined, the engine may create `ratelimit`
  rules directly (`Source: SourceSystem`, same TTL/audit path as today).
  `blocklist` rules are only ever proposed, never auto-applied — an
  operator approves via the dashboard or chat-ops bot before
  `rules.Service.Create` runs. No action auto-escalates to BGP/RTBH.
- **Chat-ops bot** — thin Slack/Telegram wrapper over the existing REST
  API (`/api/v1/rules`, `/api/v1/mitigation/*`): push threshold/TCAM
  alerts, approve/reject proposed rules, trigger `rollback`. No new auth
  model — it authenticates as an operator like any other API client.
- **Re-flag the docs** — once shipped, drop the "PLANNED / NOT YET
  IMPLEMENTED" banner from `docs/detection-thresholds.md` and correct it
  to match the real (not FastNetMon-threshold-mirrored) config shape.

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
