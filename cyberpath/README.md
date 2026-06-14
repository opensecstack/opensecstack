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

## Quick start (v0.0.1 preview — once code lands)

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

Full deployment guide will land at `docs/configuration.md` when
v0.0.1 ships. Topology in
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

## Endpoints (planned)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Liveness + DB ping |
| `GET` | `/api/v1/tracks` | List learning tracks |
| `GET` | `/api/v1/tracks/{id}` | Track detail |
| `POST` | `/api/v1/enrollments` | Enroll the caller in a track |
| `POST` | `/api/v1/lessons/{id}/complete` | Record lesson completion |
| `POST` | `/api/v1/quizzes/{id}/submit` | Submit quiz answers, get score |
| `POST` | `/api/v1/labs/{id}/start` | Start a sandbox lab session |
| `GET` | `/api/v1/cyberpath/coverage/{user_id}` | NIS2 Compass coverage query |
| `GET` | `/api/v1/cyberpath/recommend?gap=art21_g` | Gap-driven recommendation |

Full API reference: lands at `docs/api.md` with v0.0.1.

## Authentication

CyberPath authenticates users via sinauth SSO — the SIN ecosystem's
OIDC identity provider. The web dashboard uses a `sinauth.ts` client
(popup login, `/auth/callback`) implementing the authorization_code +
PKCE (S256) flow. The API validates RS256-signed access tokens against
the sinauth JWKS endpoint (`https://auth.sin.to/.well-known/jwks.json`).
See the [sinauth integration guide](../sinauth/docs/integration/cyberpath.md) for setup details.

## Configuration

Minimum required env vars (v1.0.0 target):

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

- **Phase 2 v1.0.0 — shipped**: Modules 1, 2, 3 — Learning path
  engine, quiz engine, Docker-based labs, browser terminal.
- **Phase 2 v1.0.0 — shipped 2026-05-09**: Modules 4, 5, 6, 7, 8 —
  Wasm sandbox labs, certification issuance, NIS2 Article 21(2)(g)
  WORM evidence emission to CITADEL.

See [ROADMAP.md](ROADMAP.md) for the detailed timeline.

## Contributing

CyberPath is greenfield — pre-v0.0.1 as of 2026-04-26. Early
contributors have outsized influence on the data model, the lab
runtime selection, and the certification format. See
[CONTRIBUTING.md](CONTRIBUTING.md).

Specifically open for claim once v0.0.1 lands:

- **Track content authoring** (NIS2 Article 21 awareness, phishing
  recognition, secure coding, IR basics, API security, threat-intel
  basics, Linux hardening, network forensics)
- **Wasm lab image build pipeline**
- **Browser terminal integration** (xterm.js + WebSocket relay)
- **NIS2 Compass coverage API contract**

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
