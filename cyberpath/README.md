# CyberPath — Security Training & Certification Platform

> **Status:** v1.0.0 — feature-complete (shipped 2026-05-09). Phase 2
> platform in the opensecstack ecosystem. Modules 1–8 delivered;
> third-party security audit pending scheduling.
>
> See [ADR-012](../adrs/ADR-012-cyberpath-platform-strategy.md) for
> the platform strategy rationale and the ecosystem-wide
> [ROADMAP.md § Phase 2](../ROADMAP.md) for delivery timeline.

CyberPath is the security training and certification platform in the
opensecstack (SIN) ecosystem. It exists to close a single audit gap:
**NIS2 Article 21(2)(g) requires essential and important entities to
provide cybersecurity training to staff with documented evidence of
completion.** Existing LMSes (Moodle, TalentLMS, commercial cyber-
training SaaS) treat completion as a database row. CyberPath treats
completion as immutable, signed, audit-grade evidence sealed in the
CITADEL WORM ledger.

## Module overview

CyberPath ships as a single platform with the following logical
modules across two releases:

| # | Module | Purpose | Phase | Status |
|:-:|---|---|:-:|---|
| 1 | **Learning Path Engine** | Track / module / lesson sequencing, prerequisites, progress tracking | v1.0.0 | Done |
| 2 | **Quiz & Assessment Engine** | Knowledge-check assessments with question banks and randomisation | v1.0.0 | Done |
| 3 | **Docker-Based Labs** | Hands-on lab environments via per-session Docker containers + browser terminal (xterm.js) | v1.0.0 | Done |
| 4 | **Wasm Sandbox Labs** | Lower-overhead, faster-spinup hands-on labs running pre-built lab images on a wasmtime host | v1.0.0 | Done |
| 5 | **Certification Issuance** | Per-track certification with signed, hash-anchored completion certificates | v1.0.0 | Done |
| 6 | **CITADEL Evidence Emitter** | Async `cyberpath.completion` event emission to CITADEL WORM | v1.0.0 | Done |
| 9 | **Certification Revocation Governance** | Admin revocation now emits a WORM audit entry and runs a real CITADEL MARSHAL governance check before proceeding (previously revocation had no CITADEL integration at all — not even an audit-log entry) | v1.0.0 | Done |
| 7 | **NIS2 Compass Coverage API** | `/api/v1/cyberpath/coverage/{user_id}` — query Article 21 measure coverage by user | v1.0.0 | Done |
| 8 | **Content Versioning** | Immutable content snapshots so a learner's evidence references the exact lesson revision they completed | v1.0.0 | Done |

## Why CyberPath exists

- **NIS2 Article 21(2)(g)** mandates cybersecurity training for staff
  in essential and important entities. Auditors increasingly ask not
  "did you train?" but "show me the immutable record of who completed
  what, when, against which lesson revision."
- **Existing LMSes are not audit-grade.** Moodle and TalentLMS were
  designed for academic and corporate L&D, not regulated compliance.
  Completion records are mutable, content is mutable, and there is
  no cryptographic chain to an external audit ledger.
- **Hands-on labs matter for cyber.** Slide-deck training fails the
  spirit of Article 21(2)(g). Phishing recognition needs to be
  practised against real samples; secure coding needs an editor and
  a real CVE corpus.
- **Cyber labs in browsers are still hard.** Docker-in-browser
  patterns work but are heavy; wasmtime-hosted Wasm labs cut spinup
  from minutes to seconds for lab content that doesn't need a full
  Linux userspace.

CyberPath is the missing piece between VertGuard (Module 2 — phishing
recognition has training counterparts here), IRFlow (incident-derived
training plays), and NIS2 Compass (gap-driven track recommendation).

## Quick start

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/cyberpath

cp .env.example .env
docker compose up -d

# Health check
curl http://localhost:8086/api/v1/health

# List available learning tracks
curl http://localhost:8086/api/v1/tracks
```

Full deployment guide: [docs/configuration.md](docs/configuration.md).
Topology in
[../docs/deployment-topology.md](../docs/deployment-topology.md).

## Architecture at a glance

```
                      ┌──────────────────────────┐
                      │    CyberPath API (Go)    │
                      │    :8086                 │
                      └──────────┬───────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
        ▼                        ▼                        ▼
┌───────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ React + Vite  │      │   Wasm sandbox   │      │  Integrations    │
│ frontend      │      │   (wasmtime)     │      │                  │
│ :3006         │      │                  │      │  → CITADEL WORM  │
│               │      │ • lab images     │      │  → NIS2 Compass  │
│ • shqip + en  │      │   (pre-built)    │      │  → IRFlow        │
│ • xterm.js    │      │ • per-session    │      │  → opensecstack  │
│ • lesson UI   │      │   isolation      │      │    SDK (Argon2id)│
└───────────────┘      └──────────────────┘      └──────────────────┘
```

- **Go**: HTTP API (chi), persistence (pgx), logging (zerolog), config
  (viper), metrics (prometheus). Same stack as VertGuard / APIGuard.
- **React + TypeScript + Vite**: learner UI, dashboard, browser
  terminal for Docker / Wasm labs. Bilingual (shqip + anglisht).
- **Rust + wasmtime**: v1.0.0 sandbox host. Pre-built lab images,
  per-session isolation, no host filesystem access.

Full architecture: [docs/architecture.md](docs/architecture.md).

## Certification governance: issuance vs. revocation

Certification **issuance** (`POST /api/v1/certifications/issue`, and the
auto-issue path triggered by track completion) has emitted a WORM audit
event to CITADEL (`cyberpath.certification.issued`, via the outbox
worker) since it shipped — this was not changed in the fix described
below.

Certification **revocation** (`DELETE
/api/v1/admin/certifications/{id}/revoke`) previously had **no CITADEL
integration whatsoever** — not even a plain audit-log entry. That gap
is closed:

- **WORM audit trail.** Every successful revocation now enqueues a
  `cyberpath.certification.revoked` event to CITADEL's WORM ledger
  (`internal/citadel/events.go`), mirroring the pattern issuance
  already used, plus a local `AuditEventStore` entry.
- **MARSHAL governance check.** Before the revocation is applied, the
  handler builds a Kerkese request using the real authenticated
  admin's identity and bearer token as `Actor` and submits it to
  CITADEL MARSHAL (`POST /api/v1/marshal/evaluate`). A `REFUSE` or
  `HARD_STOP` decision blocks the revocation with `403` and the
  reported reasons.

Two deliberate, documented trade-offs — not defects — apply to the
governance check and should be understood by anyone relying on this
for compliance evidence:

- **Fails open.** If CITADEL/MARSHAL is unreachable, the check logs a
  warning and the revocation proceeds anyway (matching the fail-open
  pattern used elsewhere in this codebase, e.g. APIGuard's scan
  initiation). A CITADEL outage does not block revocation — it simply
  means that particular revocation has no governance record, only the
  WORM audit entry (which is unconditional, independent of the
  MARSHAL outcome).
- **Placeholder Verifier.** The Kerkese's `Verifier` is a fixed system
  identity (`cyberpath-system-verifier`, no token), not a real second
  approver. CyberPath has no dual-control / second-approver concept
  anywhere in the codebase today, so there is nothing to wire a real
  Verifier to. This is a WARN under CITADEL's soft-mode identity/
  signature enforcement, not a block.
- The Kerkese `Action.Type` is `CONFIG_CHANGE` — CITADEL's MARSHAL RBAC
  vocabulary has no CyberPath-specific action type yet. A dedicated
  `CERTIFICATION_REVOKE` action type is a follow-up on the CITADEL
  side, out of scope for CyberPath alone.

See [docs/citadel-integration.md](docs/citadel-integration.md) for the
event schema and [docs/module-5-certification.md](docs/module-5-certification.md)
for the certification lifecycle.

## Endpoints (live)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Liveness + DB ping |
| `GET` | `/api/v1/tracks` | List learning tracks |
| `GET` | `/api/v1/tracks/{id}` | Track detail |
| `POST` | `/api/v1/enrollments` | Enroll the caller in a track |
| `POST` | `/api/v1/lessons/{id}/complete` | Record lesson completion |
| `POST` | `/api/v1/quizzes/{id}/submit` | Submit quiz answers, get score |
| `POST` | `/api/v1/labs/{id}/start` | Start a sandbox lab session |
| `POST` | `/api/v1/certifications/issue` | Issue a track certification |
| `DELETE` | `/api/v1/admin/certifications/{id}/revoke` | Revoke a certification (admin, CITADEL-governed) |
| `GET` | `/api/v1/cyberpath/coverage/{user_id}` | NIS2 Compass coverage query |
| `GET` | `/api/v1/cyberpath/recommend?gap=art21_g` | Gap-driven recommendation |

This is a representative subset — see the full, current route table
implemented in [`internal/api/server.go`](internal/api/server.go) and
documented in [docs/api.md](docs/api.md).

## Authentication

CyberPath authenticates users via sinauth SSO — the SIN ecosystem's
OIDC identity provider. The web dashboard uses a `sinauth.ts` client
(popup login, `/auth/callback`) implementing the authorization_code +
PKCE (S256) flow. The API validates RS256-signed access tokens against
the sinauth JWKS endpoint (`https://auth.sin.to/.well-known/jwks.json`).
See the [sinauth integration guide](../sinauth/docs/integration/cyberpath.md) for setup details.

## Configuration

Minimum required env vars:

```bash
CYBERPATH_DB_URL=postgres://...
CYBERPATH_CITADEL_API_URL=https://citadel.internal
CYBERPATH_CITADEL_KEY_SECRET=<hmac secret>
CYBERPATH_NIS2COMPASS_API_URL=https://nis2.internal
CYBERPATH_IRFLOW_API_URL=https://irflow.internal
```

## License

Apache 2.0. CyberPath is a tool platform — embeddable in proprietary
training pipelines and corporate LMS deployments. Permissive licence
matches APIGuard, ThreatFlow, OpenScrub, SecureLab. See
[LICENSE](LICENSE).

## Development status

- **v1.0.0 — shipped 2026-05-09**: Modules 1–8 are all delivered and
  live — learning path engine, quiz engine, Docker-based labs, browser
  terminal, Wasm sandbox labs, certification issuance (+ governed
  revocation), NIS2 Article 21(2)(g) WORM evidence emission to CITADEL,
  and content versioning.

See [ROADMAP.md](ROADMAP.md) for the historical delivery timeline and
[CHANGELOG.md](CHANGELOG.md) for the full v1.0.0 release notes.

## Contributing

CyberPath is v1.0.0 and feature-complete for its initial 8 modules —
the data model, lab runtime, and certification format are settled. New
contributors are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) for
the workflow. The areas with the most open ground for contribution:

- **Track content authoring** (NIS2 Article 21 awareness, phishing
  recognition, secure coding, IR basics, API security, threat-intel
  basics, Linux hardening, network forensics)
- **Additional Wasm lab images** on the existing build pipeline
- **v1.1 work**: per-schema tenant isolation, additional EU language
  coverage, hardware-isolated lab runtime evaluation (see
  [docs/tenancy.md](docs/tenancy.md) for the tenancy design doc and
  [ROADMAP.md](ROADMAP.md) for the rest of the v1.1 scope)

## Related

- [ADR-012: CyberPath Platform Strategy](../adrs/ADR-012-cyberpath-platform-strategy.md)
- [ECOSYSTEM.md](../ECOSYSTEM.md) — full 10-platform ecosystem overview
- [ROADMAP.md](../ROADMAP.md) — ecosystem-wide roadmap (Phase 2 entries)
- [docs/deployment-topology.md](../docs/deployment-topology.md) — ports, network segments
- [docs/architecture.md](docs/architecture.md)
- [docs/module-list.md](docs/module-list.md) — initial 8 tracks
- [docs/citadel-integration.md](docs/citadel-integration.md)
- [docs/nis2-integration.md](docs/nis2-integration.md)
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CHANGELOG.md](CHANGELOG.md)

## Security

CyberPath ships a public security policy ([SECURITY.md](SECURITY.md)).
Sandbox-escape disclosures from the Wasm lab runtime (v1.0.0) are
treated as high-severity by default — see SECURITY.md for the full
threat model and disclosure SLA.
