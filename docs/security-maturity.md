# Security Maturity Tiers

OpenSecStack v1.0.0 ships with solid cryptographic primitives, structured
audit, and role-enforced APIs. Whether it is *enough* depends on what you
are defending against. This document defines three deployment tiers so
operators can tell — from the repository — what v1.0.0 actually
guarantees and what they have to add themselves.

Each platform's own `SECURITY.md` covers reporting and the threat model
for that specific service. This document is the ecosystem-wide deployment
guidance that sits above those.

---

## TL;DR

| Your situation | Tier | Is v1.0.0 enough? |
|---|---|---|
| Single region, trusted operator, typical SaaS / NGO / public administration | **Standard** | **Yes** — production-ready |
| Multi-region, multi-tenant, zero-trust network expectations | **Elevated** | **Yes, with ops-layer additions** (Vault, service mesh, managed WAF) |
| Regulated critical infrastructure — banking Tier 1, sector CSIRTs, national utilities, NIS2 essential entities | **High assurance** | **Not yet** — wait for v1.1 or layer additional controls below |

---

## Tier 1 — Standard deployment

**For**: SaaS companies, mid-sized enterprises, NGOs, regional public
administration, research labs, internal corporate deployments.

**Threat model**: outside attackers on the public internet,
moderately-motivated insider threats, compliance with GDPR, ISO 27001,
SOC 2.

### What v1.0.0 ships, out of the box

| Control | Implementation |
|---|---|
| API authentication | HS256 JWT (per-platform secret), `exp`/`nbf` checks, `alg: none` rejected |
| Authorization | RBAC — 5 canonical roles, per-route guards (`RequireWrite`, `RequireDelete`) |
| Webhook authentication | HMAC-SHA256 with ±5 min replay window, per-source secrets, 503 on empty secret |
| Inter-service (platform → CITADEL) | HMAC-SHA256 request signing via `X-Citadel-Signature` |
| Audit integrity | CITADEL WORM chain — TripleHash (SHA-256 + SHA-512 + BLAKE3), Ed25519 anchors |
| Dual-control enforcement | CITADEL NDS protocol — every privileged action requires operator + verifier |
| Password / API-key hashing | Argon2id (RFC 9106) + HMAC-SHA256 pepper via `sdk/go/password` or `opensecstack-password` |
| Input hardening | Bounded request bodies (1 MiB default), chi timeouts, recoverer middleware, structured error envelopes |
| Observability | Structured JSON logs + Prometheus metrics + `request_id` propagation inside each service |
| Secret transport | Environment variables with file mode 0600 / container secrets |

### Standard-tier checklist before going live

- [ ] `IRFLOW_AUTH_SECRET`, `IRFLOW_AUTH_PEPPER`, `CITADEL_KEY_SECRET`, and every `*_WEBHOOK_*_SECRET` are set to ≥ 32 random bytes (`openssl rand -base64 24`)
- [ ] Secrets are not committed to git and not present in any container image
- [ ] PostgreSQL instances are on a private network segment reachable only by their owning platform
- [ ] TLS terminates at the ingress (Traefik / nginx / cloud load-balancer) in front of each platform
- [ ] Backups of the WORM table(s) run at least daily and are tested monthly
- [ ] A runbook for secret rotation exists (even if executed manually)

**v1.0.0 is production-ready at this tier.** No further code is required.

---

## Tier 2 — Elevated deployment

**For**: Multi-region SaaS with regional data residency, large enterprises
spanning several business units, organisations with internal zero-trust
mandates, deployments serving multiple tenants from one codebase.

**Threat model**: same as Standard, plus lateral movement between
regions, compromised internal subnets, insider threats with infrastructure
access, and regulatory scrutiny (e.g. SOC 2 Type II, ISO 27001).

### Additional ops-layer controls you provide

| Concern | Suggested mitigation (outside the platform code) |
|---|---|
| JWT / webhook / HMAC secrets | HashiCorp Vault, AWS KMS, GCP KMS, or Azure Key Vault as the source of truth; short-lived sidecars inject into the process at start-up |
| Network-level trust | Service mesh (Istio, Linkerd) enforcing mTLS between every platform pair; or Cloudflare Tunnel / Tailscale for east-west traffic |
| Rate limiting across platforms | Envoy filter or API gateway (Kong, Traefik Enterprise) applying shared rate-limit buckets; Redis-backed for distributed consistency |
| Distributed tracing | OpenTelemetry collector + Jaeger / Tempo; every platform accepts and forwards `traceparent` / `tracestate` headers |
| Key rotation cadence | Runbook: JWT secrets quarterly, webhook secrets on every producer deploy, CITADEL signing key yearly |
| WORM failover | Active / passive CITADEL with Consul leader-lock or Kubernetes Lease; explicit sequence number reset procedure when promoting |
| Database encryption at rest | Managed Postgres (RDS, Cloud SQL) with customer-managed keys, or `pg_tde`; separate backup encryption |

### What's still missing (known gaps, not fixable in ops)

| Gap | Impact | Status |
|---|---|---|
| JWKS endpoint on each platform | Token verification can't delegate to external IdPs without code changes | v1.1 |
| W3C Trace Context propagation across platforms | Distributed request traces break at every hop | v1.1 |
| Webhook event deduplication | A replay with a fresh timestamp + valid signature is accepted twice | v1.1 |
| CITADEL multi-writer WORM | Only single-writer WORM chain today; horizontal scale requires sharding by project | v2.0 |

**Elevated tier is achievable with v1.0.0 + standard enterprise operations
tooling (Vault, service mesh, OpenTelemetry).** No code changes required
from you; the known gaps above are ecosystem work scheduled for v1.1.

---

## Tier 3 — High-assurance deployment

**For**: Banking Tier 1, national CSIRTs, critical public utilities
(energy, water, telecom), NIS2 essential / important entities subject to
competent-authority audit, defence contractors.

**Threat model**: nation-state attackers, targeted supply-chain
compromise, insider threat with privileged credentials, long-term
stealthy compromise, mandated FIPS / Common Criteria cryptography.

### Do not deploy v1.0.0 as-is to this tier.

The following are required for high-assurance compliance. None of them
exist in v1.0.0 today — they are under consideration for v1.1 / v1.2.

| Control | Why it's required | Availability |
|---|---|---|
| FIPS 140-2 Level 3 HSM for JWT, WORM, and CITADEL signing keys | Key material must be extraction-resistant under physical attack | Post-v1.1 |
| JWKS endpoint + automated key rotation | Old tokens must stop validating immediately on rotation, not at `exp` | v1.1 |
| Mutual TLS enforced at every platform boundary | Zero-trust mandates by most regulated sectors | v1.1 |
| Webhook `event_id` deduplication table | Replay-through-reprocessed-event must be impossible, not merely unlikely | v1.1 |
| Signed audit trail for CITADEL HARD_STOP events | Forensic reconstruction must bind the event to a specific signing key | v1.1 |
| Full-source-code security audit by an independent firm (NCC Group, Trail of Bits, Cure53) | Regulators frequently require an independent pentest report | v1.1 (scheduled) |
| Forward secrecy for WORM anchors | A long-term compromise of the Ed25519 key must not retro-compromise past entries | v2.0 |
| Tamper-evident delivery / signed releases with Sigstore | Binary integrity end-to-end, not just source | v1.1 |
| Formal incident-response contract with ecosystem maintainers | Regulators require a named responsible party under SLA | Community-maintained today; formal support programme v1.1 |

### If you must deploy now at this tier

1. **Do not advertise v1.0.0 as NIS2-critical-ready** in your procurement or compliance artefacts.
2. **Compensate with operational controls**: HSM-backed Vault, strictly-segmented networks, mandatory 2-person release reviews.
3. **Track the v1.1 milestone** — every Tier 3 gap above has a planned ship date.

---

## How to interpret "v1.0.0" in documentation

Treat v1.0.0 as a quality mark, not a compliance certification. In
plain language:

> v1.0.0 means: the code compiles, the test suites pass, the API surface
> is frozen under semver, and the cryptographic primitives are
> state-of-the-art. It does **not** mean the product has passed a
> third-party security audit or that it is suitable for every deployment
> profile.

When citing v1.0.0 in external contexts:

| If your context is… | Say this |
|---|---|
| Engineering / open-source marketing | "OpenSecStack v1.0.0 is production-ready for standard deployments." |
| Mid-market enterprise buyer | "OpenSecStack v1.0.0 runs in production at SaaS scale; elevated multi-region deployments require standard enterprise tooling (Vault, service mesh)." |
| Regulated critical-infrastructure procurement | "OpenSecStack targets the high-assurance tier in v1.1 Q4 (planned); v1.0.0 is suitable for pilot and internal use, not production roll-out to regulated systems." |

---

## Roadmap references

- **v1.1** (planned, next quarter): JWKS endpoints, W3C Trace Context, webhook dedup, mTLS-ready deployment templates, third-party security audit.
- **v1.2**: CEL conditional evaluation in playbooks, automated correlation engine in ThreatFlow, signed release artefacts.
- **v2.0**: multi-writer CITADEL WORM (sharded chain), forward-secrecy WORM anchors, formal support programme for Tier 3.

See the per-platform `ROADMAP.md` for the detailed feature matrix.

---

## Cross-links

- Reporting a vulnerability → [SECURITY.md](../SECURITY.md)
- Layered defence model → [docs/security-architecture.md](./security-architecture.md)
- Per-platform threat models → `SECURITY.md` in each subdirectory
