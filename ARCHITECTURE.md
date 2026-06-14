# opensecstack (SIN) Architecture

High-level architecture of the opensecstack (SIN — Security Intelligence Network) platform ecosystem.

---

## Platform Overview

opensecstack is a collection of security and governance platforms that work together. Each platform has a defined scope and integrates with others through typed contracts.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        opensecstack ecosystem                        │
│                                                                     │
│  ┌──────────────┐    ┌───────────────┐    ┌──────────────────────┐ │
│  │   APIGuard   │    │  NIS2Compass  │    │       IRFlow         │ │
│  │              │    │               │    │                      │ │
│  │ API security │    │ NIS2 Article  │    │  Incident response   │ │
│  │ scanning     │    │ 21 compliance │    │  lifecycle           │ │
│  └──────┬───────┘    └───────┬───────┘    └──────────┬───────────┘ │
│         │                    │                        │             │
│         └────────────────────┴────────────────────────┘             │
│                              │ SDK contracts                        │
│                              │ (ScanResult, IOCBundle,              │
│                              │  IncidentRecord, AuditEntry)         │
│                              │                                      │
│                    ┌─────────▼──────────┐                          │
│                    │      CITADEL        │                          │
│                    │                    │                          │
│                    │  Governance engine  │                          │
│                    │  MARSHAL / WORM /   │                          │
│                    │  VIGIL / AUGUR      │                          │
│                    └────────────────────┘                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Platforms

| Platform | Language | Purpose | Repo |
|----------|---------|---------|------|
| APIGuard | Go + Rust + Python + React | API security scanning (OWASP API Top 10) | `apiguard/` |
| NIS2Compass | Python/FastAPI + React | NIS2 Article 21(2) compliance management | `nis2compass/` |
| CITADEL | Go | Governance engine (MARSHAL, WORM, VIGIL, AUGUR) | `.citadel/` |
| IRFlow | Go | Security incident response lifecycle | `irflow/` |
| ThreatFlow | Go | Threat intelligence and IOC management | `threatflow/` |
| OpenCSIRT | Go + React | CSIRT portal | `opencsirt/` |
| SDK | Go + Python | Typed clients and integration contracts | `sdk/` |
| OpenScrub | Rust + C + Go | XDP/eBPF DDoS mitigation, GoBGP blackhole routing | `openscrub/` |
| CyberPath | Go + React + Rust | Security training, Docker/Wasm labs, NIS2 Art.21(2)(g) | `cyberpath/` |
| SecureLab | Python + Rust + Go | Attack simulation, MITRE ATT&CK detection validation | `securelab/` |
| VertGuard | Go + Rust + Python | AI-attack defence — prompt injection, deepfake, C2PA | `vertguard/` |
| SIN Community | Go + React + TypeScript | Developer knowledge hub — posts, tags, search, spaces | `community/` |
| sinauth | Go + PostgreSQL | Identity provider — OAuth 2.0 / OIDC single sign-on for all platforms | `sinauth/` |

---

## Identity Architecture (sinauth)

sinauth is the ecosystem's identity layer — a dedicated OAuth 2.0 /
OpenID Connect authorization server. Every platform delegates end-user
and operator authentication to it instead of managing its own user
credentials.

```
Browser (platform web app)
    │  authorization_code + PKCE (S256)
    ▼
sinauth /oauth/authorize ── login + consent ── /oauth/token
    │                                              │
    │  RS256-signed ID + access tokens             │
    ▼                                              ▼
Platform validates token signature against sinauth JWKS
    (https://auth.sin.to/.well-known/jwks.json)
```

- Standards: OAuth 2.0 + OpenID Connect Core 1.0, RS256 signing, JWKS.
- Flows: authorization_code + PKCE for browser apps; refresh tokens; SSO sessions.
- MFA: TOTP (authenticator apps). Social login: Google, GitHub.
- Issuer: `https://auth.sin.to` (local: `http://localhost:8100`).
- Per-platform OIDC client setup: `sinauth/docs/integration/`.

See `sinauth/docs/architecture.md` for detail.

---

## APIGuard Architecture

APIGuard is a 10-layer API security scanning pipeline.

| Layer | Language | Responsibility |
|-------|---------|---------------|
| L1 | Rust | OpenAPI/Swagger spec parser → normalised IR |
| L2 | Go | HTTP request engine |
| L3 | Go | Authentication analysis |
| L4 | Go | Input validation and injection testing |
| L5 | Rust | Static analysis and CVSS 3.1 scoring |
| L6 | Go | OWASP API Top 10 module runner |
| L7 | Go | API server (REST + WebSocket) |
| L8 | Go | PostgreSQL persistence |
| L9 | Python | HTML/PDF report generation |
| L10 | Go | CLI |

L1 (Rust) runs as a subprocess isolated from the Go orchestrator. L5 (Rust) is a deterministic pure function embedded in the analysis pipeline.

See `apiguard/docs/architecture.md` for detail.

---

## NIS2Compass Architecture

NIS2Compass manages the 10 security measures defined in NIS2 Article 21(2).

```
FastAPI (Python) ── SQLAlchemy ── PostgreSQL
     │
     ├── JWT auth + API key auth
     ├── Evidence artifact vault
     ├── Audit log (append-only, hash-chained)
     └── Webhook emitter → CITADEL WORM log
```

Controls: `art21_a` through `art21_j` — each maps to OWASP categories and has a status lifecycle (not_assessed → in_progress → compliant/non_compliant/partially_compliant/not_applicable).

See `nis2compass/docs/` for detail.

---

## CITADEL Architecture

CITADEL is the governance engine. All sensitive operations across opensecstack platforms pass through CITADEL for authorisation.

```
Platform connectors (APIGuard, NIS2Compass, IRFlow)
    │
    │ HMAC-SHA256 signed Kerkese (action requests)
    ▼
MARSHAL (5-gate evaluation)
    │
    ├── Gate 1: Authority (SoD — actor ≠ verifier)
    ├── Gate 2: Scope (mandate and project whitelist)
    ├── Gate 3: Determinism (action is reproducible)
    ├── Gate 4: Evidence (required artifacts present)
    └── Gate 5: Schema (Kerkese v2.0 validates)
         │
         ▼
    EXECUTE | REFUSE | HARD STOP
         │
         ▼
    WORM log (append-only, hash-chained)
         │
    AUGUR (pre-emptive advisories from Odoo mirrors)
    VIGIL (GREEN/AMBER/RED health monitoring)
```

See `.citadel/docs/architecture.md` for detail.

---

## SDK

The SDK provides typed clients and integration contracts for cross-platform data exchange.

```
sdk/
├── go/opensecstack/          — Go typed clients (APIGuard, NIS2Compass, CITADEL)
├── python/opensecstack/      — Python typed clients
└── tools/tds-scanner/        — TDS compliance measurement tool
```

See `sdk/README.md` for integration contract overview.

---

## Time Dimension Segmentation (TDS)

All platforms implement TDS — operations are classified by latency tier:

| Tier | Bound | Examples |
|------|-------|---------|
| Second hand | < 300ms | MARSHAL evaluation, status polls, per-request analysis |
| Minute hand | 300ms – 30s | Report generation, standard scans, VIGIL_REALTIME |
| Hour hand | > 30s | VIGIL_DEEP, large-spec scans, batch exports |

See `adrs/ADR-009-time-dimension-segmentation.md` for the full decision record.

---

## Data Flow: Scan to Compliance

The primary integration flow from API security scan to NIS2 compliance evidence:

```
1. Developer pushes OpenAPI spec
2. APIGuard scans → ScanResult with findings
3. APIGuard emits scan_completed → CITADEL WORM log
4. APIGuard exports NIS2 evidence bundle
5. NIS2Compass receives bundle → uploads artifact
6. NIS2Compass patches art21_e control → compliant
7. NIS2Compass emits control_updated → CITADEL WORM log
8. Auditor verifies chain in CITADEL WORM log
```

---

## Governance Flow: Kerkese

Any sensitive operation (deploy, configuration change, incident response action) requires a Kerkese submission to MARSHAL:

```
1. Operator prepares Kerkese (action + evidence + actor + verifier)
2. Kerkese submitted to MARSHAL via connector
3. MARSHAL evaluates 5 gates
4. On EXECUTE: action proceeds, WORM entry written
5. On REFUSE: action blocked, reasons returned, may resubmit corrected Kerkese
6. On HARD STOP: action blocked, incident auto-created in IRFlow,
   VIGIL → RED, admin group notified
```

---

## Repository Layout

```
opensecstack/
├── apiguard/           API security scanning platform
├── nis2compass/        NIS2 compliance management
├── .citadel/           Governance engine
├── irflow/             Incident response
├── threatflow/         Threat intelligence
├── opencsirt/          CSIRT portal
├── sdk/                Go + Python SDK and tools
├── openscrub/          XDP/eBPF DDoS mitigation
├── cyberpath/          Security training platform
├── securelab/          Attack simulation and detection validation
├── vertguard/          AI-attack defence
├── community/          SIN developer knowledge hub
├── sinauth/            Identity provider (OAuth2 / OIDC SSO)
├── adrs/               Architecture Decision Records
├── docs/               Cross-platform documentation
└── ARCHITECTURE.md     This file
```
