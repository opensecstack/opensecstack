# VertGuard Security Model

## Threat boundaries

VertGuard sits between **untrusted user-facing applications** (chat
clients, document upload portals, identity verification frontends) and
**trusted backend systems** (LLM gateways, KYC pipelines, SIEM
ingest). Every endpoint is a boundary; this document enumerates the
threats VertGuard defends against, the controls in place, and the
threats it explicitly does **not** address.

---

## Trust zones

```
┌──────────────────────┐  HTTPS+JWT  ┌───────────────────┐
│ Calling application  │────────────▶│   VertGuard API   │
│ (LLM gateway, KYC)   │             │  (chi + middleware) │
└──────────────────────┘             └─────────┬─────────┘
        │                                       │
        │ scan/verify                           │ scan rows
        │   request                             ▼
        │                                ┌──────────────┐
        │                                │  PostgreSQL  │
        │                                └──────────────┘
        │                                       │
        │                                       │ WORM emission (HMAC)
        │                                       ▼
        │                                ┌──────────────┐
        │                                │   CITADEL    │
        │                                └──────────────┘
        │                                       │
        ▼                                       ▼
┌──────────────────────┐    HMAC     ┌──────────────────┐
│ Outbound subscribers │◀────────────│  Webhook fanout  │
│ (IRFlow, ThreatFlow) │             └──────────────────┘
└──────────────────────┘
```

---

## STRIDE per request

For a `POST /api/v1/scan/prompt` call:

| Threat | Concrete risk | Control |
|--------|--------------|---------|
| **Spoofing** | Caller forges another tenant's identity | JWT HS256 with per-tenant secret; API-key → JWT exchange; bootstrap keys env-only |
| **Tampering (in transit)** | Proxy modifies prompt mid-flight | TLS at the perimeter; in zero-trust deployments, mTLS via the service mesh |
| **Tampering (at rest)** | Operator edits a scan row to hide a `BLOCKED` event | Every scan emits a WORM entry to CITADEL keyed on the scan UUID. The DB row alone is not the source of truth — discrepancy is detectable. |
| **Repudiation** | Caller denies sending a malicious prompt | `audit_events` row records `actor`, `request_id`, `remote_ip`, `metadata`. Hash chain in CITADEL is the tamper-evident audit. |
| **Information disclosure (prompt)** | DB compromise reveals user prompts | **Privacy-by-schema** — only `input_hash` (SHA-256) is stored, never the prompt itself. |
| **Information disclosure (secret)** | Operator leaks JWT signing secret | Secrets sourced exclusively from the secrets-management config (Vault, AWS Secrets Manager). Never logged, never exposed via API. See [secrets-management.md](secrets-management.md). |
| **Denial of service** | Attacker floods scan endpoint | Token-bucket rate limit per JWT subject + per source IP; per-subject overrides via `rate_limit_overrides`. Circuit breaker (`internal/breaker`) sheds load when downstream ML inference saturates. |
| **Elevation of privilege** | `viewer` role mutates IOC corpus | Role hierarchy enforced in middleware; mutation endpoints require `operator` or `admin`. Denylist lookup on every request prevents stolen-token abuse. |

---

## Authentication

- **API keys** — `tf_<64-hex>`-style opaque secrets, stored as SHA-256
  hashes (`api_keys.key_hash`). Plaintext shown once at creation.
- **JWT (HS256)** — Issued via `POST /api/v1/auth/token` with a 60-minute
  default TTL. Tokens carry `sub`, `role`, `kind`, `iat`, `exp`, `jti`.
- **Bootstrap keys** — Env-var-only plaintext keys mapped to `admin`
  for first-boot provisioning. Production deployments must rotate to
  DB-backed keys after the first admin onboards.

JWT verification fails closed on:

1. Bad signature
2. Expired token (`exp` in past)
3. JTI present in `token_denylist`
4. Subject present in `token_denylist` (whole-subject revocation)

---

## Authorisation

Roles form a strict hierarchy:

```
viewer  <  analyst  <  operator  <  admin
```

| Endpoint class | Required role |
|----------------|---------------|
| `GET /api/v1/scan/*` (read history) | `viewer` |
| `POST /api/v1/scan/*` (perform scan) | `analyst` |
| `POST /api/v1/threats/iocs` (mutate IOC corpus) | `operator` |
| `POST /api/v1/webhooks` (manage subscribers) | `admin` |
| `POST /api/v1/admin/denylist` (revoke tokens) | `admin` |

Middleware uses `auth.AtLeast(have, required)`; missing token → 401,
insufficient role → 403.

---

## Privacy

VertGuard's strongest control is **what it refuses to store**:

- No prompt text, image bytes, document body, identity payload.
- Scan rows hold SHA-256 hashes (`input_hash`, `claim_hash`,
  `content_hash`).
- Pattern matches store *pattern IDs and positions*, not the matching
  substring.
- Audit events store `metadata` as structured JSONB — never the raw
  request body.

Operators with full DB read access can replay analytics ("how often did
input X recur?") via `input_hash`, but cannot reconstruct any
particular user's input. See the privacy section in
[data-model.md](data-model.md).

### Right to erasure

Because VertGuard never stores raw content, GDPR Art. 17 erasure
requests are typically a no-op. Where the calling application has
asserted a link between a `scan_id` and a natural person (out of
band), VertGuard supports targeted deletion via:

```
DELETE /api/v1/admin/scans/<scan_id>
```

The deletion is itself a `DATA_DELETE` audit event, so the act of
erasure is auditable.

---

## Cryptography

| Use | Algorithm | Key length |
|-----|-----------|-----------|
| JWT signing | HS256 (HMAC-SHA-256) | ≥ 256 bits |
| API-key hashing | SHA-256 | n/a |
| Webhook payload signing | HMAC-SHA-256 | ≥ 256 bits |
| CITADEL connector signing | HMAC-SHA-256 | ≥ 256 bits |
| TripleHash content fingerprint | SHA-256 + perceptual hash | n/a |
| TLS (perimeter) | TLS 1.3 | per cert |

**Post-quantum readiness** — The HMAC and SHA-256 primitives above are
PQ-resistant in the symmetric-key sense (Grover halves effective bit
strength; 256-bit keys remain secure). For *signing* (JWT-style
asymmetric), see [`docs/post-quantum-roadmap.md`](../../docs/post-quantum-roadmap.md)
in the opensecstack umbrella repo for the planned migration to
ML-DSA / SLH-DSA.

---

## Logging & telemetry

- Logs are JSON, structured via zerolog. **Never** logged: JWT
  contents, API-key plaintext, prompt/image bodies, `request.body`.
- Logged: `request_id`, `actor`, `role`, `action`, `outcome`,
  `duration_ms`, `status_code`, `remote_ip`.
- `request_id` is generated by chi middleware and propagates to
  CITADEL emissions and webhook payloads — supporting end-to-end
  trace correlation.

Log retention is the operator's responsibility; the recommended
default is 90 days hot + 1 year cold.

---

## Threats out of scope

VertGuard does **not** defend against:

- **Compromise of the calling application.** If the LLM gateway is
  attacker-controlled, it can choose not to call VertGuard. Detection
  must come from network-layer instrumentation (APIGuard).
- **Supply-chain attack on the model artefact.** A malicious model
  registered through the model registry can produce attacker-chosen
  outputs. Mitigation: signed model cards (planned in v1.1) and
  registry RBAC.
- **CITADEL service compromise.** WORM events are tamper-evident
  *given* a trustworthy chain anchor. If CITADEL itself is rooted, the
  chain anchor is suspect. Mitigate by replicating chain anchors to an
  external observer (e.g. a public timestamp authority).
- **DoS at the network layer.** Token-bucket helps, but absorbing
  large-scale floods is a job for upstream WAF / CDN.

---

## Compliance evidence

VertGuard contributes evidence into:

- **NIS2 Article 21** — incident detection (Module 1/2/3) and
  audit-trail requirements via CITADEL WORM. Mappings in
  [nis2-ai-act-mapping.md](nis2-ai-act-mapping.md).
- **EU AI Act** — Annex III high-risk system controls (logging,
  oversight, robustness). See the AI-Act column in the same file.
- **ISO 27001** — A.5.10 (information classification),
  A.8.2 (privileged access), A.8.15 (logging), A.8.24 (cryptography).

The control-to-evidence map is generated daily by the
`vertguard compliance export` command and consumed by NIS2 Compass.

---

## Vulnerability handling

See [SECURITY.md](../SECURITY.md). Summary:

1. Email `security@opensecstack.org` (PGP key in `SECURITY.md`).
2. Acknowledgement within 2 business days.
3. Triage + advisory within 14 days.
4. Fix release + CVE assignment.

Coordinated disclosure window: 90 days.

---

## See Also

- [secrets-management.md](secrets-management.md) — key sources + rotation
- [data-model.md](data-model.md) — schema-level privacy guarantees
- [citadel-integration.md](citadel-integration.md) — WORM + governance
- [nis2-ai-act-mapping.md](nis2-ai-act-mapping.md) — regulatory mapping
- [SECURITY.md](../SECURITY.md) — vulnerability disclosure policy
