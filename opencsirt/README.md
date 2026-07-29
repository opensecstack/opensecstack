# OpenCSIRT — National/Sector CSIRT Operations Platform

> **Status:** v1.0.0 — feature complete (shipped 2026-05-10). Phase 3
> platform in the opensecstack ecosystem. Constituency directory,
> incident coordination, CSAF 2.0 advisory authoring, peer-CSIRT
> handshake, and CITADEL-attested evidence.
>
> See the [OpenCSIRT ROADMAP.md](ROADMAP.md) for post-1.0 direction,
> and the [monorepo ECOSYSTEM.md](https://github.com/opensecstack/opensecstack/blob/main/ECOSYSTEM.md) for ecosystem context.

OpenCSIRT is the governance-tier CSIRT operations platform in the
opensecstack (SIN) ecosystem. It exists to give a national or sector
CSIRT a single working surface for the four jobs the team actually
does:

1. **Constituency tracking** — who you serve, sector, NIS2 status,
   contact-of-record. The directory the rest of the platform keys
   off.
2. **Incident coordination** — abuse-mailbox triage, IRFlow handoffs,
   peer-CSIRT escalations. Every state change is signed into CITADEL
   so the timeline survives a vendor swap.
3. **Advisory authoring** — CSAF 2.0 documents drafted in the Python
   advisory subsystem, reviewed by `csirt_lead`, published with TLP
   enforcement to constituents and federated peers.
4. **Federated trust** — peer CSIRTs read advisories at their TLP
   tier, push back IOC bundles, and receive escalations over a
   handshake protocol that does not require shared MISP infrastructure.

OpenCSIRT does not replace IRFlow's per-incident workflow engine, and
it does not pretend to be a SIEM. It is the layer that turns IRFlow
incidents and ThreatFlow IOCs into advisories, NIS2 notifications,
and a peer-shareable record.

## Module overview

| # | Module | Purpose | Status |
|:-:|---|---|---|
| 1 | **Go API (`cmd/opencsirt`)** | REST API on `:8088` — constituencies, incidents, advisories, peers, integrations | Done |
| 2 | **Python advisory subsystem** | CSAF 2.0 generation/validation on `:8089`, called by the Go core | Done |
| 3 | **PostgreSQL 16 persistence** | Constituency directory, incidents, advisories, peers, CITADEL outbox | Done |
| 4 | **React + Vite dashboard** | Operator UI on `:3088` — incidents board, advisory editor, peer roster | Done |
| 5 | **CITADEL evidence emitter** | Async outbox → `opencsirt.*` events (incidents, advisories, escalations) | Done |
| 6 | **ThreatFlow IOC ingest** | Pull IOC bundles, attach to incidents, fan-out to advisories | Done |
| 7 | **IRFlow incident webhook** | HMAC-signed inbound — IRFlow incidents become OpenCSIRT incidents | Done |
| 8 | **NIS2 Compass notifier** | Push NIS2 Article 23 notifications upstream when severity threshold crosses | Done |
| 9 | **VertGuard subscriber** | Pull CVE advisories from VertGuard, embed into outbound CSAF | Done |
| 10 | **JWT auth (6 roles)** | viewer · external_peer · analyst · operator · csirt_lead · admin | Done |
| 11 | **Prometheus + JSON snapshot** | Operator metrics; dashboard reads `/api/v1/metrics/snapshot` | Done |

## Why OpenCSIRT exists

- **NIS2 Article 11** requires Member States to designate CSIRTs with
  documented incident handling, advisory dissemination, and
  cross-border cooperation. OpenCSIRT is the working surface for
  those three jobs in one place.
- **CSAF 2.0 is the format**, not STIX. NIS2 advisories, CVD
  coordination, and vendor advisories all converge on CSAF — having a
  CSAF-native generator is no longer optional for a serious CSIRT.
- **Federated peer trust without MISP hard-requirement.** OpenCSIRT
  ships its own JWT-gated handshake protocol; MISP integration is on
  the roadmap (post-1.0) for sites that want it, but the platform is
  usable from day 1 without it.

## Architecture at a glance

```
                ┌──────────────────────────────────────────┐
                │       OpenCSIRT API (Go)                 │
                │       :8088                              │
                │  constituencies · incidents · advisories │
                │  peers · integrations · auth (6 roles)   │
                └──────┬─────────────────────┬─────────────┘
                       │                     │
        ┌──────────────┘                     └──────────────┐
        │                                                   │
        ▼                                                   ▼
┌──────────────────────┐                     ┌──────────────────────────┐
│ Python advisory      │                     │  PostgreSQL 16           │
│ subsystem            │                     │  constituencies ·        │
│ :8089                │                     │  incidents · advisories  │
│  CSAF 2.0 gen + val  │                     │  peers · citadel_outbox  │
└──────────────────────┘                     └──────────────────────────┘
                       │
                       ▼
                ┌──────────────────────┐
                │ React + Vite SPA     │
                │ :3088                │
                │  incidents board     │
                │  advisory editor     │
                │  peer roster         │
                └──────────────────────┘
```

Integrations:

```
   ThreatFlow ─── IOC pull ──────►  OpenCSIRT  ──── CSAF advisory ─►  External
                                       │   ▲                          peers
   IRFlow ─── incident webhook ────►   │   │
                                       │   │
   VertGuard ─── CVE subscriber ───►   │   │
                                       │   │
                       NIS2 Compass ◄──┘   │
                       (Article 23)        │
                                           │
                       CITADEL  ◄── opencsirt.{incident,advisory,
                       (WORM)        escalation}_* events
```

- **Go**: HTTP API (chi), persistence (pgx), logging (zerolog),
  metrics (prometheus). Same stack as OpenScrub / IRFlow / CyberPath.
- **Python 3.11**: FastAPI advisory subsystem; CSAF 2.0 schema
  validation; called over HTTP by the Go core. Runs in its own
  container ([python/](python/)).
- **React + TypeScript + Vite**: operator UI.

Full architecture: [docs/architecture.md](docs/architecture.md).

## Endpoints

OpenCSIRT serves its REST API on **port 8088**. Highlights (full
contract: [api/openapi.yaml](api/openapi.yaml)):

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Liveness — `{status, db, advisory_service, uptime_seconds}` |
| `POST` | `/api/v1/auth/login` | JWT issuance |
| `GET` `POST` | `/api/v1/constituencies` | Directory CRUD |
| `GET` `POST` | `/api/v1/incidents` | Triage queue + open new |
| `POST` | `/api/v1/incidents/{id}/close` | Close + emit CITADEL event |
| `GET` `POST` | `/api/v1/advisories` | Draft + list (CSAF 2.0) |
| `POST` | `/api/v1/advisories/{id}/publish` | Publish, enforce TLP, fan out to peers |
| `POST` | `/api/v1/integrations/irflow/incident` | HMAC-signed IRFlow webhook |
| `GET` | `/api/v1/metrics` | Prometheus exposition (JWT-gated) |
| `GET` | `/api/v1/metrics/snapshot` | JSON dashboard snapshot |

## Port reservations

| Service | Port | Notes |
|---|:-:|---|
| Go API | `8088` | `OPENCSIRT_HTTP_ADDR` |
| Python advisory subsystem | `8089` | `OPENCSIRT_ADVISORY_SERVICE_URL` |
| React dashboard | `3088` | nginx in production, `vite dev` locally |
| PostgreSQL | `5432` | cluster-internal |

See the [monorepo deployment-topology.md](https://github.com/opensecstack/opensecstack/blob/main/docs/deployment-topology.md)
for the ecosystem-wide port map.

## Configuration

Minimum required env vars (full list in
[docs/configuration.md](docs/configuration.md), env template in
[.env.example](.env.example)):

```bash
OPENCSIRT_DB_URL=postgres://opencsirt:opencsirt@postgres:5432/opencsirt
OPENCSIRT_JWT_SECRET=<32+ random bytes>
OPENCSIRT_PASSWORD_PEPPER=<32+ random bytes>
OPENCSIRT_USERS=operator:operator:<sha256hex>
OPENCSIRT_ADVISORY_SERVICE_URL=http://advisory:8089
OPENCSIRT_CITADEL_API_URL=https://citadel.internal
OPENCSIRT_CITADEL_HMAC_SECRETS=<hmac>
OPENCSIRT_CITADEL_PROJECT_ID=opencsirt
OPENCSIRT_THREATFLOW_API_URL=https://threatflow.internal
OPENCSIRT_IRFLOW_WEBHOOK_SECRET=<hmac>
```

## Authentication

OpenCSIRT authenticates web dashboard users via **sinauth** SSO, the
SIN ecosystem identity provider. Authentication uses OAuth 2.0 / OIDC
with the `authorization_code` + PKCE (S256) flow; the dashboard's
`sinauth.ts` client handles the popup login and `/auth/callback` route.
The API validates RS256-signed tokens against the sinauth JWKS endpoint
(`https://auth.sin.to/.well-known/jwks.json`). See the
[OpenCSIRT sinauth integration guide](../sinauth/docs/integration/opencsirt.md).

## CITADEL governance

OpenCSIRT integrates with CITADEL in two ways:

- **WORM evidence (audit-only).** Incident open/close, advisory
  publish, and escalation events are emitted to CITADEL's
  `POST /api/v1/worm/emit` after the fact, as the tamper-evident
  timeline required by NIS2 Article 21(2)(c)/23.
- **MARSHAL evaluation (blocking).** Advisory publication and
  incident closure are evaluated against CITADEL MARSHAL
  (`POST /api/v1/marshal/evaluate`) *before* they are allowed to
  proceed, using the authenticated caller's real identity, and are
  blocked (HTTP 403) on a `REFUSE`/`HARD_STOP` verdict.

**Known limitation:** the MARSHAL check's Verifier is a fixed system
placeholder — OpenCSIRT has no real second-approver workflow yet — and
CITADEL's RBAC map does not yet recognize OpenCSIRT's `ADVISORY_PUBLISH`
action or cover most of OpenCSIRT's roles for `INCIDENT_CLOSE` (only
`admin` is currently permitted). In practice this means most real
evaluate calls legitimately `REFUSE` at CITADEL's AuthZ gate today,
until CITADEL's RBAC map is extended on the CITADEL side. See
[docs/citadel-integration.md](docs/citadel-integration.md) for the
full write-up of both gaps.

## License

**AGPL-3.0-or-later.** OpenCSIRT is governance tier — same licence as
CITADEL, VertGuard, IRFlow. Operating an OpenCSIRT instance as a
network service triggers AGPL § 13: source for any modifications must
be made available to users of that service. See [LICENSE](LICENSE) and the
[monorepo ECOSYSTEM.md — Licensing Model](https://github.com/opensecstack/opensecstack/blob/main/ECOSYSTEM.md#licensing-model).

## Development status

- **Phase 3 v1.0.0 — shipped 2026-05-10**: full module set 1–11.
  Feature complete. See [CHANGELOG.md](CHANGELOG.md) for the line
  items.

See [ROADMAP.md](ROADMAP.md) for post-1.0 direction.

## Related

- [ECOSYSTEM.md](https://github.com/opensecstack/opensecstack/blob/main/ECOSYSTEM.md) — full ecosystem overview
- [ROADMAP.md](ROADMAP.md) — OpenCSIRT roadmap
- [CHANGELOG.md](CHANGELOG.md)
- [SECURITY.md](SECURITY.md) — disclosure tiers
- [CONTRIBUTING.md](CONTRIBUTING.md) — three-zone split
- [docs/quick-start.md](docs/quick-start.md)
- [docs/operator-handbook.md](docs/operator-handbook.md)
- [docs/faq.md](docs/faq.md)
- [docs/troubleshooting.md](docs/troubleshooting.md)

## Security

OpenCSIRT ships a public security policy ([SECURITY.md](SECURITY.md)).
**Incident-data confidentiality is the highest-tier disclosure
class** — incident payloads, peer-CSIRT identifiers, and TLP:RED
advisories must never leak. There is no kernel attack surface in
OpenCSIRT (the platform is pure userspace Go + Python + React); the
threat model is application-tier.
