## CyberPath Compliance Traceability Matrix

Maps CyberPath controls to the frameworks an EU NIS-scope auditor
will reference. Evidence cites repository paths so each row can be
verified against the source of truth. Rows marked "Gap: Y" point at
`security-checklist.md` for the remediation entry.

CyberPath's primary regulatory hook is **NIS2 Article 21(2)** —
specifically (g) cyber hygiene + training, the load-bearing measure
for which CyberPath is the audit-grade evidence source. Companion
mappings for AI Act, GDPR Article 32, ISO 27001, and OWASP ASVS L2
follow.

### 1. NIS2 (Directive (EU) 2022/2555) — Article 21(2)

| Measure | Title | Requirement | CyberPath implementation | Gap | Notes |
|---|---|---|---|:-:|---|
| (a) | Risk analysis & info-system security policies | Policies for risk analysis and security of information systems | `docs/security/threat-model.md` (STRIDE-lite); operator runs a CyberPath instance under their own ISMS | N | Track 1 also covers staff awareness of the policy |
| (b) | Incident handling | Detect, handle, and report incidents | IRFlow webhook integration consumes incident signals; Track 4 (IR basics) and Track 8 (Network forensics) train responders; audit middleware + CITADEL WORM emit | N | Notification automation is operator-side (NIS2 Compass) |
| (c) | Business continuity | Backup, DR, crisis management | PodDisruptionBudget, HPA, breaker on outbound RPCs, bounded async queue + WAL for CITADEL; Track 7 (Linux hardening) covers operator-side BCP | N | DR drill schedule is operator responsibility |
| (d) | Supply-chain security | Supplier risk; deps | `go.sum`, `Cargo.lock`, `package-lock.json`, lab-image SHA-256 + Cosign signatures, SBOM (CycloneDX) at release; Track 5 (API security) covers supply-chain considerations for engineers | N | govulncheck / cargo audit / npm audit wired in CI per checklist 7.4–7.7 |
| (e) | Acquisition / dev / maintenance security | Security in sys acquisition, dev, maintenance | 2-reviewer rule on sandbox-touching changes (CODEOWNERS); semgrep custom rules; content-quality linter; Tracks 3 + 5 directly train this measure | N | — |
| (f) | Effectiveness assessment | Policies and procedures for assessing effectiveness | Coverage endpoint feeds NIS2 Compass which performs assessment; CyberPath records the input | N | Assessment surface is NIS2 Compass, not CyberPath |
| (g) | **Cyber hygiene + training** | Basic cyber hygiene practices and cybersecurity training | **Primary CyberPath driver.** Audit-grade completion records (`completions` immutable; `content_version_id` references immutable revision; CITADEL WORM mirror; Ed25519-signed certifications). Tracks 1–8 cover operational, engineering, and SOC populations | N | Article 21(2)(g) is the load-bearing measure for which CyberPath is the evidence source |
| (h) | Cryptography & encryption | Policies on cryptography use | HMAC-SHA256 webhooks, Ed25519 certifications, BLAKE3 evidence hash, TLS at ingress; Track 7 covers staff-level crypto hygiene | N | C2PA / Ed25519 PQC tracked in ADR-011 |
| (i) | HR security & access control | Identity, RBAC, training awareness | opensecstack/sdk auth + RBAC; per-tenant isolation; Tracks 1, 2, 6 train this measure | N | Coarse 4-role model (learner / instructor / operator / admin) |
| (j) | MFA / continuous auth / secure comms | Use of MFA, continuous auth, secure comms | TLS at ingress; MFA-on-login for CyberPath itself is on the v1.x roadmap (Track 9 candidate covers user-facing MFA) | Y | Tracked under residual risk in `threat-model.md § 7` |

NIS2 Article 23 (incident reporting): CyberPath records audit
events and emits to CITADEL WORM; the 24h-initial / 72h-notification
flow is owned by the operator's SOC tooling.

### 2. AI Act (EU) 2024/1689 — applicability

CyberPath is **largely not in scope** of the EU AI Act because:

- It does not deploy a general-purpose AI model (Title VIIIA).
- Its primary functions (track delivery, quiz scoring, completion
  signing, lab orchestration) are not high-risk AI systems under
  Annex III.
- It does not perform biometric identification, social scoring, or
  any of the prohibited practices in Article 5.

| Article | Requirement | CyberPath position |
|---|---|---|
| Art. 5 | Prohibited AI practices | N/A — none used |
| Art. 6 + Annex III | High-risk AI systems | N/A — CyberPath is a training platform, not an AI system that takes consequential decisions |
| Art. 50 | Transparency obligations | N/A — CyberPath does not generate synthetic content or interact with users as an AI |

**Borderline area: training-content recommendation across tenant
boundaries.** The `/api/v1/cyberpath/recommend` endpoint maps a
NIS2 Article 21 measure to track recommendations. Today this is a
deterministic gap-to-track lookup — not "AI" in any meaningful
sense, and not high-risk. **If a future iteration introduces
ML-based recommendation that crosses tenant boundaries (e.g.,
"learners in tenant A who completed track X also benefited from
track Y"), that would trigger an AI-Act applicability re-review**:
the cross-tenant signal in particular would push it toward
Annex III scrutiny because it produces career-affecting outputs
(training assignments) for individual learners. Tracked as a
v2.x design constraint.

### 3. GDPR Article 32 — Security of processing

| Requirement | CyberPath implementation | Evidence |
|---|---|---|
| Pseudonymisation | Learner PII separable from completion records via `user_id` indirection | `docs/architecture.md § PostgreSQL schema`; Right-to-erasure redacts PII fields, leaves completion chain anchored to pseudonymous id |
| Encryption | TLS at ingress; Argon2id for passwords; Ed25519 for cert signatures; HMAC-SHA256 for webhooks | `SECURITY.md § Post-quantum strategy` |
| Confidentiality of processing | Per-tenant isolation; sandbox per-session isolation; no cross-cohort state | `threat-model.md § TB-13`, § 4.2 |
| Integrity of processing | Append-only `completions`; `content_versions` immutable; CITADEL WORM mirror | `architecture.md § PostgreSQL schema` notes |
| Availability + resilience | PDB, HPA, circuit breakers, bounded async queue + WAL | `security-checklist.md § 6, § 10` |
| Restoration after incident | DB backup (operator); Helm re-install; lab-image registry independent | operator handbook (lands with v1.0) |
| Regular testing | Pre-release security checklist; pentest before v1.0.0; quarterly threat-model review | `pre-audit-plan.md`, `security-checklist.md § 11` |
| Risk-appropriate measures | Threat model documents proportionality | `threat-model.md` |

DPIA template lands with v1.0.0; the per-control GDPR Article 32
evidence above is the interim DPIA scope referenced from
`SECURITY.md § Data handling`.

### 4. ISO/IEC 27001:2022 — control families touched

| Annex A family | Title | CyberPath touchpoint |
|---|---|---|
| A.5 | Organisational policies | `SECURITY.md`, root `SECURITY.md`, this document set |
| A.6 | People controls | CONTRIBUTING.md (contributor agreements); CODEOWNERS for sandbox changes |
| A.8 | Asset management | Helm `values.yaml`, OpenAPI surface (`api/openapi.yaml`), lab-image registry (`labs/labs.yaml`), SBOM at release |
| A.9 | Access control | opensecstack/sdk auth, RBAC, JWT denylist (per sdk), per-tenant isolation |
| A.12 | Operations security | Audit middleware, structured logs, Prometheus metrics, runbook |
| A.14 | System acquisition, development, maintenance | 2-reviewer rule for sandbox; semgrep / content-lint in CI; ADR process |
| A.16 | Information security incident management | `disclosure.md`, IRFlow integration, operator runbook IR playbooks |
| A.17 | Business continuity | PDB, HPA, async queue + WAL, breaker pattern |

CyberPath does not claim ISO 27001 certification of itself; it
provides controls a deployer can use within their own ISMS.

### 5. OWASP ASVS Level 2 — target

CyberPath targets **OWASP Application Security Verification Standard
Level 2** (defence-in-depth, suitable for applications handling
sensitive business data) for v1.0.0. Selected controls:

| ASVS § | Control | CyberPath | Gap |
|---|---|---|:-:|
| V1 Architecture | Threat model documented | `threat-model.md` | N |
| V2 Authentication | Cryptographic password storage | Argon2id via opensecstack/sdk | N |
| V2.1 / V2.2 | MFA available for high-value accounts | Roadmap v1.x | Y (deferred; tracked) |
| V3 Session management | Bounded TTL, server-side revocation | sdk JWT denylist; `auth.token_ttl=8h` | N |
| V4 Access control | Deny-by-default, RBAC enforced | Role wrappers per route; tenant filter at query layer | N |
| V5 Validation, sanitisation, encoding | Input validation; output encoding | JSON-only API; struct-typed unmarshal; React escapes; CSP | N |
| V7 Error handling, logging | No sensitive data in logs; structured logs; audit | zerolog field-select; audit middleware | N |
| V8 Data protection | Sensitive data encrypted in transit + at rest | TLS at ingress; DB ssl_mode=require; KMS-backed cert key | N |
| V9 Communication | TLS, secure headers | Ingress TLS; CSP `default-src 'self'`, `frame-ancestors 'none'` | N |
| V10 Malicious code | No code execution from untrusted input outside sandbox | Sandbox is the explicit place where untrusted code runs; `image-signing.md` chain controls what enters the sandbox | N |
| V11 Business logic | Anti-automation | Per-account login lockout; per-tenant lab quota | N |
| V12 Files / resources | Path traversal guards | `filepath.Clean` + base-dir check; content-lint | N |
| V13 API and web service | API contract enforced | OpenAPI source-of-truth; generated TS client | N |
| V14 Configuration | Secure defaults; refuse-to-start in prod with insecure config | `Config.EnforceProductionGate` | N |

ASVS Level 3 (mission-critical, exhaustive) is not a v1.0 target;
revisit at v2.0 once MFA, fine-grained ACLs, and continuous fuzzing
ship.

### 6. Apache 2.0 content licensing note

Track content (lessons, quizzes, lab YAMLs) under `content/tracks/`
is published under the **Apache License, Version 2.0**, the same
licence as the platform code. This has compliance implications
worth recording explicitly:

- **Content is intellectual capital but is not access-restricted
  by licence.** A NIS2 deployer can fork, adapt, and self-host the
  content without commercial barrier.
- **Apache 2.0 grants a patent licence covering the content as it
  ships.** Forks that add new training material grant the same
  patent terms back upstream when contributed.
- **Attribution survives forks.** A NIS2-audit-grade derivative
  must retain the `NOTICE` file and content-author attribution; an
  auditor verifying "where did this training come from" can trace
  it back to the upstream commit.
- **The content-author identity model in `image-signing.md` is
  separate from the licence.** Apache 2.0 controls reuse rights;
  Sigstore identity controls who can publish a *signed* track that
  CyberPath will install by default.

This licensing posture is a deliberate choice: CyberPath is the
sovereign EU NIS2 training platform, and gating the training
content behind a commercial licence would defeat the purpose.

### 7. Gap summary

| Framework | Open gap | Tracked in |
|---|---|---|
| NIS2 (j) | MFA-on-login for CyberPath itself | checklist 2.7 (residual); `threat-model.md § 7` |
| ASVS V2.1/V2.2 | Same MFA gap | as above |
| AI Act borderline | ML-based recommend across tenants | v2.x design constraint, no current code |

All open gaps are scoped Small or Medium and either fit inside the
T-30d window in `pre-audit-plan.md` or are formally accepted as
v1.x roadmap items.

### 8. Related

- `threat-model.md`
- `security-checklist.md` — gap inventory
- `disclosure.md` — disclosure SLA referenced by ASVS V14
- `pre-audit-plan.md`
- `image-signing.md` — content-author trust hierarchy
- `../adrs/ADR-012-cyberpath-platform-strategy.md`
