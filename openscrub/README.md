# OpenScrub — DDoS Mitigation Platform

> **Status:** v1.0.0 — feature complete (shipped 2026-05-09). Phase 2
> platform in the opensecstack ecosystem. XDP/eBPF data plane, Go
> control-plane API, ThreatFlow IOC pull, and CITADEL-attested
> mitigation evidence.
>
> See the ecosystem-wide [ROADMAP.md](../ROADMAP.md) and
> [ECOSYSTEM.md](../ECOSYSTEM.md) for context.

OpenScrub is the DDoS mitigation platform in the opensecstack (SIN)
ecosystem. It exists to close two operational gaps:

1. **Line-rate L3/L4 mitigation** without a commercial scrubbing
   appliance — XDP/eBPF in-kernel filtering at NIC ingress, sub-µs
   per-packet decisions, no userspace copy on the drop path.
2. **Audit-grade mitigation evidence** — every block decision emits a
   signed `openscrub.mitigation` event into CITADEL WORM, so a NIS2
   auditor can reconstruct *which* IP was blocked, *why* (rule, IOC
   source), and *when* — without trusting a vendor log.

OpenScrub does not replace upstream BGP-based scrubbing for volumetric
attacks past NIC capacity. It is the on-prem first-line filter that
stops everything below that threshold and gives the operator a
honest, signed record of what it did.

## Module overview

| # | Module | Purpose | Status |
|:-:|---|---|---|
| 1 | **XDP loader (Rust + Aya)** | Loads the kernel program at NIC ingress, manages BPF maps | Done |
| 2 | **eBPF/C data plane** | Per-packet `XDP_DROP` / `XDP_PASS` decisions against the blocklist map | Done |
| 3 | **Go control-plane API** | REST API on `:8087` — rules CRUD, mitigations live, metrics | Done |
| 4 | **ThreatFlow IOC puller** | Periodic pull of malicious-IP IOCs from ThreatFlow into the BPF blocklist map | Done |
| 5 | **PostgreSQL persistence** | Rule history, mitigation log, audit trail | Done |
| 6 | **React + Vite dashboard** | Rules list, add rule, live mitigations, metrics — bilingual (sq/en) | Done |
| 7 | **CITADEL evidence emitter** | Async `openscrub.mitigation` event emission to CITADEL WORM | Done |
| 8 | **Prometheus metrics** | `pps_dropped`, `pps_passed`, `rules_active`, `ioc_pull_latency_ms` | Done |

## Why OpenScrub exists

- **Commercial scrubbers are expensive and opaque.** A line-rate XDP
  drop costs the same in CPU regardless of whether the operator owns
  the source code. Owning the source code matters for audit.
- **NIS2 Article 21(2)(c) — incident handling** requires documented
  evidence of mitigation actions. A commercial scrubber's CSV export
  is not WORM, not signed, and not chained.
- **ThreatFlow already has the IOCs.** OpenScrub is the consumer of
  the malicious-IP feed ThreatFlow already aggregates. Closing this
  loop turns an intel feed into an enforced blocklist with no
  human-in-the-middle copy-paste.

## Quick start

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/openscrub

cp .env.example .env
docker compose -f deploy/docker-compose.yml up -d

# Health check
curl http://localhost:8087/api/v1/health

# List active rules
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8087/api/v1/rules
```

Full deployment guide: [docs/deployment.md](docs/deployment.md). Port
assignments and ecosystem topology in
[../docs/deployment-topology.md](../docs/deployment-topology.md).

## Architecture at a glance

```
                  ┌────────────────────────────────────┐
                  │       OpenScrub API (Go)           │
                  │       :8087                        │
                  │  rules · mitigations · metrics     │
                  └──────────────┬─────────────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
        ▼                        ▼                        ▼
┌────────────────┐    ┌────────────────────┐    ┌──────────────────┐
│ React + Vite   │    │  PostgreSQL 16     │    │  Integrations    │
│ dashboard      │    │  rules · audit     │    │                  │
│ :3087          │    │                    │    │ → CITADEL WORM   │
│                │    └────────────────────┘    │ → ThreatFlow     │
│ • shqip + en   │                              │   (IOC pull)     │
│ • rules CRUD   │    ┌────────────────────┐    │ → Prometheus     │
│ • live miti    │◄───┤  Prometheus :9090  │    │ → SDK            │
└────────────────┘    └────────────────────┘    └────────┬─────────┘
                                                         │
                  ┌──────────────────────────────────────┘
                  │
                  ▼
   ┌──────────────────────────────────────────────────────────┐
   │            OpenScrub dataplane (Rust + Aya)              │
   │  CAP_BPF · CAP_NET_ADMIN · CAP_SYS_RESOURCE              │
   │  privileged=false · hostNetwork=true · drop=ALL          │
   │                                                          │
   │   ┌──────────────────────────────────────────────────┐   │
   │   │   eBPF/C program — XDP at NIC ingress           │   │
   │   │   ┌──────────────┐    ┌─────────────────────┐    │   │
   │   │   │ blocklist    │    │ rate-limit map      │    │   │
   │   │   │ map (LPM)    │    │ (pps per CIDR)      │    │   │
   │   │   └──────────────┘    └─────────────────────┘    │   │
   │   │           │                       │              │   │
   │   │           ▼                       ▼              │   │
   │   │       XDP_DROP                XDP_PASS           │   │
   │   └──────────────────────────────────────────────────┘   │
   └──────────────────────────────────────────────────────────┘
                              ▲
                              │  NIC RX queue
                              │
                       ┌──────┴──────┐
                       │   network   │
                       └─────────────┘
```

- **Go**: HTTP API (chi), persistence (pgx), logging (zerolog), config
  (viper), metrics (prometheus). Same stack as APIGuard / CyberPath.
- **Rust + Aya**: userspace dataplane. Pins maps to `/sys/fs/bpf`,
  manages program lifecycle, exposes a Unix-socket control plane the
  Go API talks to. Runs with `privileged: false` and an explicit
  `CAP_BPF + CAP_NET_ADMIN + CAP_SYS_RESOURCE` set on top of `drop:
  ALL` — see [docs/security/threat-model.md](docs/security/threat-model.md).
- **C (eBPF)**: per-packet program. LPM-trie blocklist + per-CIDR
  rate-limit map. No userspace copy on drop.
- **React + TypeScript + Vite**: operator UI. Bilingual (shqip + en).

Full architecture: [docs/architecture.md](docs/architecture.md).

## Endpoints

OpenScrub serves its REST API on **port 8087**.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Liveness — `{status, version, db_ping, dataplane_attached}` |
| `POST` | `/api/v1/auth/login` | JWT issuance — `{access_token, token_type, expires_at, role, sub}` |
| `GET` | `/api/v1/rules?limit=&offset=&type=` | List rules — `{rules, count}` |
| `POST` | `/api/v1/rules` | Create rule (`type` ∈ `blocklist`/`ratelimit`/`syncookie`) |
| `GET` | `/api/v1/rules/{id}` | Rule detail |
| `DELETE` | `/api/v1/rules/{id}` | Withdraw rule (clears BPF map entry) |
| `GET` | `/api/v1/mitigations?since=&rule_id=&limit=` | Mitigation rows — `{mitigations, count}` |
| `GET` | `/api/v1/metrics/snapshot` | JSON metrics snapshot for the dashboard |
| `GET` | `/api/v1/metrics` | Prometheus exposition (text) — JWT-gated |

Full API reference: [docs/api.md](docs/api.md). Machine-readable
contract: [api/openapi.yaml](api/openapi.yaml).

## Configuration

Minimum required env vars (full list in
[docs/configuration.md](docs/configuration.md)):

```bash
OPENSCRUB_DB_URL=postgres://openscrub:openscrub@postgres:5432/openscrub
OPENSCRUB_DATAPLANE_SOCKET=/run/openscrub/dataplane.sock
OPENSCRUB_JWT_SECRET=<32+ random bytes>
OPENSCRUB_CITADEL_API_URL=https://citadel.internal
OPENSCRUB_CITADEL_HMAC_SECRET=<hmac secret>
OPENSCRUB_THREATFLOW_API_URL=https://threatflow.internal
OPENSCRUB_THREATFLOW_TOKEN=<bearer token>
OPENSCRUB_IFACE=eth0
```

## Authentication

OpenScrub authenticates web dashboard users via **sinauth** SSO, the
SIN ecosystem identity provider. Authentication uses OAuth 2.0 / OIDC
with the `authorization_code` + PKCE (S256) flow; the dashboard's
`sinauth.ts` client handles the popup login and `/auth/callback` route.
The API validates RS256-signed tokens against the sinauth JWKS endpoint
(`https://auth.sin.to/.well-known/jwks.json`). See the
[OpenScrub sinauth integration guide](../sinauth/docs/integration/openscrub.md).

## License

Apache 2.0. OpenScrub is a tool platform — embeddable in proprietary
edge stacks. Permissive licence matches APIGuard, ThreatFlow,
CyberPath, SecureLab. See [LICENSE](LICENSE) and
[ECOSYSTEM.md § Licensing Model](../ECOSYSTEM.md#licensing-model).

## Development status

- **Phase 2 v1.0.0 — shipped 2026-05-09**: full module set 1–8.
  Feature complete. Third-party kernel-attack-surface audit pending
  scheduling.

See [ROADMAP.md](ROADMAP.md) for the detailed timeline and post-1.0
plans.

## Related

- [ECOSYSTEM.md](../ECOSYSTEM.md) — full 10-platform ecosystem overview
- [ROADMAP.md](ROADMAP.md) — OpenScrub roadmap
- [../docs/deployment-topology.md](../docs/deployment-topology.md) — port 8087 reservation
- [docs/architecture.md](docs/architecture.md)
- [docs/security/threat-model.md](docs/security/threat-model.md) — STRIDE for the kernel attack surface
- [docs/threatflow-integration.md](docs/threatflow-integration.md)
- [docs/citadel-integration.md](docs/citadel-integration.md)
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CHANGELOG.md](CHANGELOG.md)

## Security

OpenScrub ships a public security policy ([SECURITY.md](SECURITY.md)).
**Kernel-attack-surface findings (XDP map injection, rule poisoning,
loader privilege escalation) are treated as critical-severity by
default** — the data plane runs with `CAP_BPF` + `CAP_NET_ADMIN` and
any escape into host kernel state is in the highest disclosure tier.
See [docs/security/threat-model.md](docs/security/threat-model.md) for the full model.
