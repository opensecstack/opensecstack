# Security Architecture — Five-Layer Defence Model

opensecstack is protected by five concentric security layers. Each layer is independent — a breach of one does not automatically compromise the others. Together they form a defence-in-depth model that covers identity, network, host, application, and data.

---

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 5 — DATA FENCE                                           │
│  WORM log · TripleHash · Chain anchors · DR · Triple backup     │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Layer 4 — APPLICATION FENCE                              │  │
│  │  APIGuard · MARSHAL · VIGIL · AUGUR · Input validation    │  │
│  │                                                           │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │  Layer 3 — HOST FENCE                               │  │  │
│  │  │  Kubernetes · Least-privilege containers · Pinned   │  │  │
│  │  │  dependencies · Supply chain verification          │  │  │
│  │  │                                                     │  │  │
│  │  │  ┌───────────────────────────────────────────────┐  │  │  │
│  │  │  │  Layer 2 — NETWORK FENCE                      │  │  │  │
│  │  │  │  Rate limiting · CORS · TLS · Replay          │  │  │  │
│  │  │  │  protection · Trusted proxy · Isolation       │  │  │  │
│  │  │  │                                               │  │  │  │
│  │  │  │  ┌─────────────────────────────────────────┐  │  │  │  │
│  │  │  │  │  Layer 1 — IDENTITY FENCE               │  │  │  │  │
│  │  │  │  │  JWT · API keys · HMAC-SHA256 · SoD     │  │  │  │  │
│  │  │  │  │  Role groups · Token revocation         │  │  │  │  │
│  │  │  │  └─────────────────────────────────────────┘  │  │  │  │
│  │  │  └───────────────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer 1 — Identity Fence

**Goal**: Prevent user accounts and service credentials from being stolen or misused.

### Mechanisms

| Mechanism | Platform | Detail |
|-----------|---------|--------|
| JWT authentication | APIGuard, NIS2Compass | Short-lived tokens (1 hour expiry), signed with platform key |
| Refresh token revocation | APIGuard, NIS2Compass | Tokens individually revocable; revocation state checked on every request |
| API key authentication | APIGuard, NIS2Compass, CITADEL | Keys hashed at rest (bcrypt); shown once on creation |
| HMAC-SHA256 connector signing | CITADEL | Per-request signature over key_id + timestamp + body hash |
| Timestamp replay protection | CITADEL | ±300 second window; seen (key_id, ts, sig) tuples rejected |
| Separation of Duties (SoD) | CITADEL MARSHAL Gate 1 | `actor.user_id ≠ verifier.user_id` — enforced cryptographically, not by policy |
| Role-based group membership | CITADEL | group_sig_admin, group_sig_operator, group_sig_verifier, group_sig_auditor |
| API key validation logging | APIGuard | All validation failures logged with correlation ID |

### Known gaps

- No MFA enforcement at application level — relies on identity provider
- Session invalidation on password change not yet implemented across all platforms

### Reference docs

- [apiguard/docs/security.md](../apiguard/docs/security.md)
- [.citadel/docs/security-model.md](../.citadel/docs/security-model.md)
- [.citadel/docs/sod.md](../.citadel/docs/sod.md)

---

## Layer 2 — Network Fence

**Goal**: Prevent network-level penetration, traffic interception, and request flooding.

### Mechanisms

| Mechanism | Platform | Detail |
|-----------|---------|--------|
| Rate limiting | APIGuard, NIS2Compass | Redis atomic Lua sliding-window; per key/IP |
| CORS enforcement | NIS2Compass | Strict origin allowlist in production; rejects cross-origin requests from unknown origins |
| TLS required | All platforms | TLS 1.2 minimum; documented in operator handbooks |
| Trusted proxy handling | APIGuard | Explicit trusted CIDR list; prevents IP spoofing via X-Forwarded-For |
| Admin API isolation | CITADEL | Admin endpoints not exposed to general internal network |
| CITADEL connector isolation | CITADEL | Connector API on separate internal port; not internet-routable |
| Mirror DB network isolation | CITADEL AUGUR | Mirror PostgreSQL read-only replicas accessible only from CITADEL components |

### Known gaps

- No WAF (Web Application Firewall) at the perimeter — planned for infrastructure layer
- Kubernetes NetworkPolicy not yet defined — all pods can reach each other within namespace
- DDoS mitigation relies on upstream infrastructure (CDN/load balancer), not implemented at application level

### Reference docs

- [apiguard/docs/operator-handbook.md](../apiguard/docs/operator-handbook.md)
- [nis2compass/docs/deployment.md](../nis2compass/docs/deployment.md)
- [.citadel/docs/security-model.md](../.citadel/docs/security-model.md)

---

## Layer 3 — Host Fence

**Goal**: Prevent exploitation of host operating system and software vulnerabilities.

### Mechanisms

| Mechanism | Platform | Detail |
|-----------|---------|--------|
| Kubernetes deployment | APIGuard, NIS2Compass | Containers with defined resource limits and requests |
| Least-privilege containers | All | Non-root container execution; read-only root filesystem where possible |
| Dependency pinning | NIS2Compass | All Python dependencies pinned to exact versions in requirements.txt |
| Supply chain notes | APIGuard | Documented in security.md — Go module checksums, cargo lock |
| Secrets manager integration | All | No secrets in environment variables or config files; secrets manager required |
| Separate DB roles | CITADEL, APIGuard, NIS2Compass | Least-privilege PostgreSQL roles per component (reader/writer/auditor) |

### Known gaps

- Container image scanning (Trivy, Grype) not integrated into CI/CD pipeline
- SBOM (Software Bill of Materials) not generated for any platform
- Kubernetes seccomp and AppArmor profiles not defined
- OS-level patching policy not documented — depends on base image update cadence
- Go/Rust/Python dependency vulnerability scanning not automated (Dependabot configured but not enforced)

### Reference docs

- [apiguard/docs/security.md](../apiguard/docs/security.md)
- [nis2compass/docs/security-model.md](../nis2compass/docs/security-model.md)

---

## Layer 4 — Application Fence

**Goal**: Prevent exploitation of vulnerabilities in the opensecstack ecosystem itself.

### Mechanisms

| Mechanism | Platform | Detail |
|-----------|---------|--------|
| OWASP API Top 10 scanning | APIGuard | All 10 categories (a1_bola through a10_unsafe_consumption) — APIGuard scans its own ecosystem |
| MARSHAL 5-gate governance | CITADEL | Every sensitive action evaluated: Authority, Scope, Determinism, Evidence, Schema |
| Hard Stop + auto-incident | CITADEL | SoD violation, spoofing, contradictory evidence → immediate P1 incident |
| AUGUR pre-emptive advisories | CITADEL | AUG-001 through AUG-009 — proactive warnings before violations occur |
| VIGIL real-time monitoring | CITADEL | GREEN/AMBER/RED — chain integrity, mirror freshness, anchor age, active incidents |
| VIGIL_DEEP daily audit | CITADEL | Full WORM chain verification, SoD compliance scan, orphan detection |
| Input validation | APIGuard, NIS2Compass | Request body size limits, type validation, SSRF prevention, injection guards |
| Correlation IDs | APIGuard | Every request tagged for cross-component tracing |
| Security headers | APIGuard | HSTS, X-Content-Type-Options, X-Frame-Options, CSP |
| Kerkese schema validation | CITADEL MARSHAL Gate 5 | Strict schema enforcement on every governance request |

### Unique property

APIGuard scans the opensecstack APIs themselves. This creates a closed loop: the application fence continuously tests itself. Any new vulnerability introduced into the ecosystem's own APIs will be detected by the next scheduled scan.

### Known gaps

- No static application security testing (SAST) in CI/CD pipeline
- Penetration testing schedule not defined
- GraphQL endpoints (if added in future) require separate scanning module

### Reference docs

- [apiguard/docs/architecture.md](../apiguard/docs/architecture.md)
- [.citadel/docs/architecture.md](../.citadel/docs/architecture.md)
- [.citadel/docs/marshal.md](../.citadel/docs/marshal.md)
- [.citadel/docs/vigil.md](../.citadel/docs/vigil.md)
- [.citadel/docs/augur.md](../.citadel/docs/augur.md)
- [.citadel/docs/hard-stop-playbook.md](../.citadel/docs/hard-stop-playbook.md)

---

## Layer 5 — Data Fence

**Goal**: Prevent data deletion, tampering, and ensure recovery to a verified-clean state after any failure.

### Mechanisms

| Mechanism | Platform | Detail |
|-----------|---------|--------|
| WORM log — append-only | CITADEL | PostgreSQL immutability trigger prevents UPDATE and DELETE on worm.log |
| SHA-256 hash chain | CITADEL | Every entry hashes content + prev_hash — any modification breaks the chain |
| TripleHash (Blake3 + SHA-256 + SHA-512) | vantage-hash (Rust) | 128-byte composite digest — all three algorithms must be broken simultaneously to forge |
| Ed25519-signed chain anchors | CITADEL | Periodic anchors signed with rotating Ed25519 key; optional external notarisation |
| VIGIL_DEEP chain verification | CITADEL | Daily recomputation of entire chain hash — detects any tampering |
| Tamper-evident audit log | NIS2Compass | Hash-chained audit entries; chain verifiable via API |
| Same-city active-active | Architecture | Zero-RPO failover — no governance gap during primary failure |
| Offsite disaster recovery | Architecture | Geographically separate standby — survives regional failure |
| Triple backup | Architecture | Three independent copies — survives destruction of primary and DR simultaneously |
| Signed WORM exports | CITADEL | Ed25519-signed JSONL export — integrity verifiable after recovery |
| Signed VIGIL_DEEP reports | CITADEL | Reports stored in evidence vault and WORM-logged — tamper-evident audit trail |

### Key property: recovery integrity

Most disaster recovery systems restore data but cannot prove the restored data matches the original. The TripleHash + WORM chain means that after any recovery — even from the coldest backup — the restored log can be cryptographically verified against the original chain anchors. Tampered recovery is detectable.

### Known gaps

- External notarisation of chain anchors is optional — not enforced by default. Without it, anchor integrity depends solely on the CITADEL signing key.
- Active-active MARSHAL consensus protocol not yet defined — two active nodes could produce split-chain if they write simultaneously without coordination (see planned ADR)
- Backup encryption at rest not yet documented as a requirement

### Reference docs

- [.citadel/docs/worm-log.md](../.citadel/docs/worm-log.md)
- [.citadel/docs/triple-hash.md](../.citadel/docs/triple-hash.md)
- [.citadel/docs/chain-anchor.md](../.citadel/docs/chain-anchor.md)
- [.citadel/docs/data-model.md](../.citadel/docs/data-model.md)
- [nis2compass/docs/audit-log.md](../nis2compass/docs/audit-log.md)

---

## Defence-in-Depth Matrix

How layers stop specific attack scenarios:

| Attack scenario | Layer stopped at | Mechanism |
|----------------|-----------------|-----------|
| Stolen API key used to submit Kerkese | Layer 1 | SoD — stolen key cannot also control the verifier account |
| Replay of valid signed request | Layer 1 | Timestamp window + nonce deduplication |
| Brute-force MARSHAL with repeated REFUSE | Layer 4 | Brute-force pattern → HARD STOP |
| SQL injection in APIGuard scan target | Layer 4 | Input validation + parameterised queries |
| Insider self-approves sensitive action | Layer 1 + Layer 4 | SoD (L1) + MARSHAL Gate 1 (L4) |
| Attacker deletes WORM log entries | Layer 5 | Immutability trigger — DELETE raises exception |
| Attacker modifies WORM log entries | Layer 5 | Chain hash breaks — VIGIL_DEEP detects on next scan |
| Primary database destroyed | Layer 5 | Active-active failover → offsite DR → triple backup |
| Recovered data tampered with | Layer 5 | TripleHash + chain anchor proves tampering |
| New vulnerability in opensecstack API | Layer 4 | APIGuard scans own ecosystem — detected on next scan |
| Container escape from compromised pod | Layer 3 | Least-privilege containers limit blast radius |
| DDoS against API endpoints | Layer 2 | Rate limiting + upstream infrastructure |
| Mirror ERP database compromised | Layer 2 + Layer 4 | Mirror is read-only (L2); mirror data does not affect MARSHAL gate decisions (L4) |

---

## Current Security Posture

```
Layer 1 — Identity     ████████████  Strong
Layer 2 — Network      ████████░░░░  App-level solid; WAF and NetworkPolicy missing
Layer 3 — Host         ████░░░░░░░░  Container basics in place; SBOM and scanning missing
Layer 4 — Application  ████████████  Closed-loop self-scanning; strongest layer
Layer 5 — Data         ███████████░  Cryptographic integrity assured; notary optional
```

Layers 1, 4, and 5 are production-grade. Layers 2 and 3 require infrastructure investment to reach the same level. The gaps are documented, bounded, and addressable — they are not unknown unknowns.

---

## NIS2 Article 21(2) Mapping

| NIS2 measure | Primary layer | opensecstack component |
|---|---|---|
| (a) Risk analysis and security policies | L4 | CITADEL governance, NIS2Compass art21_a |
| (b) Incident handling | L4 + L5 | IRFlow, CITADEL WORM log, SOP-012 |
| (c) Business continuity and DR | L5 | Active-active + offsite DR + triple backup |
| (d) Supply chain security | L3 | Dependency pinning, Go module checksums |
| (e) Security in network and systems | L2 + L3 | Rate limiting, TLS, k8s isolation |
| (f) Effectiveness of security measures | L4 | APIGuard scans, VIGIL_DEEP, quarterly drills |
| (g) Cyber hygiene and training | L1 | SoD enforcement, role model |
| (h) Cryptography | L5 | TripleHash, Ed25519 anchors, HMAC-SHA256 |
| (i) Human resources security | L1 | Role groups, access revocation |
| (j) Access control | L1 + L4 | JWT/API keys, MARSHAL gate evaluation |
