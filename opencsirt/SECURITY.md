# OpenCSIRT Security Policy

> **Canonical threat model:** [docs/security/](docs/security/) — STRIDE
> for incident-data leakage, advisory tampering, peer impersonation,
> CITADEL HMAC bypass, and webhook spoofing. Read this before
> contributing to `internal/auth/`, `internal/citadel/`, or the peer
> handshake.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities** —
this exposes deployers and, more importantly for OpenCSIRT, exposes
operational CSIRT data before a fix is available. **Incident-data
leakage is treated as critical-severity by default** and routed
directly to the core security team.

| Channel | Address | Use for |
|---|---|---|
| GitHub Security Advisory | `github.com/opensecstack/opensecstack/security/advisories/new` | Preferred. Private. GitHub handles coordination. |
| Email | `security@opensecstack.org` | Alternative if GitHub advisory not accessible. |
| PGP encrypted email | Fingerprint published at `https://opensecstack.org/.well-known/security.txt` | Any vulnerability that touches incident payloads, peer identifiers, or TLP:AMBER/RED advisory contents. |

See the [monorepo SECURITY.md](https://github.com/opensecstack/opensecstack/blob/main/SECURITY.md) for ecosystem-wide
disclosure policy and response SLA.

## Scope

**IN SCOPE:**

- Go API server ([cmd/opencsirt/](cmd/opencsirt/), [internal/](internal/))
- Python advisory subsystem ([python/](python/))
- React frontend ([web/](web/))
- JWT issuance, role enforcement, password hashing
  ([internal/auth/auth.go](internal/auth/auth.go))
- CITADEL outbox emitter and watcher ([internal/citadel/](internal/citadel/))
- IRFlow inbound webhook (`/api/v1/integrations/irflow/incident`)
- ThreatFlow IOC ingest puller and validation
- NIS2 Compass notifier
- VertGuard subscriber
- Peer-CSIRT handshake protocol
  ([docs/peer-csirt-handshake-protocol.md](docs/peer-csirt-handshake-protocol.md))
- TLP enforcement on advisory read
- Docker images published to `ghcr.io/opensecstack/opencsirt-*`
- Helm chart at [deploy/helm/opencsirt/](deploy/helm/opencsirt/)

**OUT OF SCOPE:**

- Linux kernel itself — there is no kernel attack surface in
  OpenCSIRT (pure userspace Go + Python + React)
- CSAF 2.0 schema correctness against the OASIS spec — raise upstream
- ThreatFlow IOC accuracy — raise as a ThreatFlow content issue
- IRFlow's own auth model — raise on IRFlow
- Postgres / nginx CVEs — track upstream advisories

## Severity classification

OpenCSIRT uses four tiers. **Incident-data confidentiality is the
top tier.**

| Tier | Examples | Triage SLA | Fix SLA |
|---|---|---|---|
| **Critical** | Incident-data leak, advisory tampering with auth bypass, CITADEL HMAC bypass, JWT forgery, peer-CSIRT impersonation | 24 h | 7 days |
| **High** | TLP enforcement bypass on advisory read, IRFlow webhook spoofing (HMAC drift / replay), VertGuard webhook spoofing, role-escalation in `internal/auth/`, sensitive-data leak via metrics | 72 h | 30 days |
| **Medium** | DoS of the API, audit-log gaps, dashboard XSS, advisory-subsystem RCE that does not reach the Go core | 7 days | 90 days |
| **Low** | Hardening recommendations, defence-in-depth requests | 30 days | next release |

## Threat model summary

Full threat model: [docs/security/](docs/security/). The five axes
that get the most scrutiny:

1. **Incident-data leak.** An adversary reads incident rows they
   should not. Mitigations: role-gated reads, TLP enforcement, no
   unauthenticated metrics endpoint, no incident bodies in logs.
2. **Advisory tampering.** An adversary modifies a draft advisory or
   forges a `published` state without the `csirt_lead` role.
   Mitigations: role check on publish, CITADEL append-only emission
   on every state change, signed CSAF doc.
3. **CITADEL HMAC bypass.** An adversary forges or replays an
   `opencsirt.*` event into CITADEL. Mitigations: HMAC-SHA256 with
   `OPENCSIRT_CITADEL_HMAC_SECRETS`, ±5-minute replay window
   enforced server-side, key rotation via comma-separated secrets.
4. **JWT forgery.** An adversary mints a valid token without
   knowing the secret. Mitigations: `OPENCSIRT_JWT_SECRET` ≥32 bytes
   enforced outside dev mode, multi-secret rotation, short TTL
   (`OPENCSIRT_TOKEN_TTL`, default 12 h).
5. **IRFlow / VertGuard webhook spoofing.** An adversary replays an
   old or forged webhook. Mitigations: HMAC-SHA256 with
   `OPENCSIRT_IRFLOW_WEBHOOK_SECRET`, ±5-minute replay window,
   constant-time signature comparison.

## Hardening defaults

- **`/api/v1/metrics` is JWT-gated** — counters reveal operational
  state (incident counts, advisory cadence, peer escalation rate),
  so the endpoint requires a Bearer token. Provision a long-lived
  "readonly" JWT for Prometheus.
- **Login issuer disables** when `OPENCSIRT_USERS` is empty —
  `/api/v1/auth/login` returns `503 issuer_disabled`. Operators
  must mint JWTs out-of-band against `OPENCSIRT_JWT_SECRET` until
  users are configured.
- **Password pepper is required outside dev mode.** A pepper
  containing `do-not-use-in-prod` is rejected at startup
  ([`internal/config/config.go`](internal/config/config.go)).
- **CITADEL dry-run defaults to true.** Production deployments must
  set `OPENCSIRT_CITADEL_DRY_RUN=false` and provision real HMAC
  secrets.
- **TLS termination at the ingress.** OpenCSIRT does not terminate
  TLS itself; deploy behind nginx / Envoy / a managed LB.
- **All inter-platform webhooks HMAC-SHA256 signed** with ±5-minute
  replay window.

## Disclosure terms

We follow standard coordinated disclosure with a 90-day default
embargo, extendable by mutual agreement. Reporters credited in the
advisory unless they prefer anonymity. Findings that touch live
incident data of a constituency may be embargoed past 90 days while
the affected CSIRT is notified — this is a deliberate exception for
CSIRT operations.

## Related

- [docs/security/](docs/security/) — full threat model
- [docs/peer-csirt-handshake-protocol.md](docs/peer-csirt-handshake-protocol.md)
- [docs/citadel-integration.md](docs/citadel-integration.md)
- [docs/irflow-integration.md](docs/irflow-integration.md)
- [monorepo SECURITY.md](https://github.com/opensecstack/opensecstack/blob/main/SECURITY.md) — ecosystem disclosure policy
- [CONTRIBUTING.md](CONTRIBUTING.md)
