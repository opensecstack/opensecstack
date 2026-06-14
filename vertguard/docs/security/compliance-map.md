## VertGuard Compliance Traceability Matrix

Maps VertGuard controls to the frameworks an EU NIS-scope auditor
will reference. Evidence cites repository paths so each row can be
verified against the source of truth. Rows marked "Gap: Y" point at
`security-checklist.md` for the remediation entry.

### 1. NIS2 (Directive (EU) 2022/2555)

| Control area | Article | Requirement | VertGuard implementation | Gap | Notes |
|---|---|---|---|:-:|---|
| Incident reporting | Art. 23 | Detect and notify incidents within 24h initial / 72h notification | Audit middleware (`internal/audit/middleware.go`) + CITADEL WORM emit (`internal/citadel/client.go`); operator runbook §5 escalation matrix | N | Notification automation is operator-side |
| Risk management | Art. 21(2)(a) | Risk analysis policy | `docs/security/threat-model.md` | N | Quarterly review cadence |
| Business continuity | Art. 21(2)(c) | Backup, DR | PodDisruptionBudget (`templates/pdb.yaml`), HPA, breaker (`internal/breaker/breaker.go`), bounded async queue with drop-on-full | N | DR drill schedule is operator responsibility |
| Supply-chain security | Art. 21(2)(d) | Supplier risk, deps | `go.sum`, `Cargo.lock`, model SHA-256 in `models.yaml`, SBOM at release | Y | `govulncheck` / `cargo audit` not yet in CI (checklist 7.4–7.5) |
| Crypto | Art. 21(2)(h) | Use of cryptography | HMAC-SHA256 webhooks, HS256 JWT, SHA-256 input hash, PQC roadmap (`SECURITY.md`, ADR-011) | N | C2PA Ed25519 PQC tracked |
| Access control | Art. 21(2)(i) | Identity, RBAC | `internal/auth/jwt.go`, `auth/middleware.go`, `auth/roles.go`; denylist (`internal/auth/denylist`) | N | Coarse 5-role; fine-grained scopes are v1+ |
| Logging | Art. 21(2)(g) | Security monitoring | zerolog structured logs, Prometheus `/metrics`, audit channel `audit:true` flag | N | Log shipping is operator-side |

### 2. OWASP Top 10 (2021)

| ID | Category | VertGuard implementation | Gap |
|---|---|---|:-:|
| A01 | Broken Access Control | `RequireRead/Write/Admin` per route (`internal/api/server.go:111-189`); `IsKnownRole` allowlist | N |
| A02 | Cryptographic Failures | HS256 JWT with constant-time compare; HMAC-SHA256 webhooks; no plaintext content in DB; ssl_mode=require | N |
| A03 | Injection | pgx parameterised queries (`internal/db/*_store.go`); JSON-only API; no shell-out except c2pa-verify with arg list | N |
| A04 | Insecure Design | STRIDE-lite threat model; ADRs gate architectural change | N |
| A05 | Security Misconfiguration | Helm defaults: nonroot, RO root FS, drop ALL, seccomp RuntimeDefault, NetworkPolicy template | Y | NetworkPolicy off-by-default; sign images with cosign (checklist 6.13) |
| A06 | Vulnerable and Outdated Components | Pinned `go.sum` / `Cargo.lock`; SBOM at release | Y | CI vuln scan not yet wired |
| A07 | Identification and Authentication Failures | HS256 + denylist + dual-secret rotation; bounded TTL | Y | Refuse-to-start in prod when dev_mode (checklist 2.10) |
| A08 | Software and Data Integrity Failures | Image SHA pin in chart; `models.yaml` SHA-256; `Cargo.lock` | Y | Cosign image signing not wired |
| A09 | Security Logging and Monitoring Failures | Audit middleware on every mutation; CITADEL mirror; `IncAuditEvent` metric; structured logs | N | — |
| A10 | Server-Side Request Forgery | No user-supplied URL fetch in API surface (Phase 4.1) | N/A | Re-evaluate when media upload + remote fetch lands |

### 3. OWASP LLM Top 10 (2023) — what VertGuard defends

| ID | Threat | VG defence | Where |
|---|---|---|---|
| LLM01 | Prompt Injection | Pattern-based scanner with confidence tiers (CLEAN/SUSPICIOUS/BLOCKED); operator threshold control; CITADEL evidence emit | `internal/prompt/scanner.go`, `module-3-prompt-injection.md` |
| LLM02 | Insecure Output Handling | Out of scope (consumer concern); VG is the upstream firewall | — |
| LLM03 | Training Data Poisoning | SHA-256 checksums in `models.yaml`; dataset registry | `SECURITY.md § Supply chain` |
| LLM04 | Model DoS | Input size cap, rate limiter, breaker, request timeout | `internal/ratelimit`, `internal/breaker` |
| LLM05 | Supply Chain | `Cargo.lock`, `go.sum`, model checksums, SBOM | — |
| LLM06 | Sensitive Information Disclosure | Input hashed before storage (SHA-256); never persists raw text | `internal/prompt/scanner.go:151-158` |
| LLM07 | Insecure Plugin Design | N/A (no plugin model in v0.1) | — |
| LLM08 | Excessive Agency | N/A | — |
| LLM09 | Overreliance | Confidence is a contract (`SECURITY.md § design principles`); operators set thresholds | — |
| LLM10 | Model Theft | mTLS planned for ML side-car (ADR-012); model registry verified at load | — |

Coverage doc: `docs/owasp-llm-top10-coverage.md`.

### 4. MITRE ATLAS

VertGuard ships an ATLAS technique mapping endpoint
(`POST /api/v1/threatfeed/atlas`) and a coverage report
(`GET /api/v1/threatfeed/atlas/coverage`). Detection coverage is
tracked in `docs/mitre-atlas-mapping.md`. Techniques actively
defended by Phase 4.1:

| Technique | Name | Defence surface |
|---|---|---|
| AML.T0051.000 | LLM Prompt Injection: Direct | Module 3 pattern engine |
| AML.T0051.001 | LLM Prompt Injection: Indirect | Module 3 pattern engine |
| AML.T0054 | LLM Jailbreak | Module 3 + denylist of seen-jailbreak prompts |
| AML.T0040 | ML Model Inference API Access | Rate limiter + RBAC |
| AML.T0048 | External Harms (Reputational) | Audit + CITADEL evidence |
| AML.T0024 | Exfiltration via ML Inference API | Output handling boundary (advisory; consumer-side) |

Sync source: `internal/threatfeed/atlas/`, refreshed via
`POST /api/v1/admin/atlas/sync` (admin-only).

### 5. NIST Cybersecurity Framework 2.0

| Function | Control | Evidence |
|---|---|---|
| **Identify** (ID) | Asset inventory | Helm `values.yaml`, OpenAPI surface (`api/openapi.yaml`) |
| | Risk assessment | `threat-model.md` |
| | Supply-chain risk | `models.yaml`, `go.sum`, `Cargo.lock`, SBOM |
| **Protect** (PR) | Access control | `internal/auth/*` |
| | Awareness training | `docs/operator-runbook.md` + CONTRIBUTING |
| | Data security | Input-hash rule, no raw retention default, content_retention opt-in |
| | Information protection | RBAC, denylist, audit |
| | Maintenance | Helm rolling update, PDB |
| | Protective tech | Distroless, RO FS, NetworkPolicy template, breaker, rate limiter |
| **Detect** (DE) | Anomalies | Pattern engine, ATLAS mapping, threat feed |
| | Continuous monitoring | Prometheus metrics, structured logs, audit |
| | Detection processes | `tests/adversarial/`, `tests/fp/`, quarterly pattern refresh |
| **Respond** (RS) | Response planning | `docs/operator-runbook.md` (10 playbooks) |
| | Communications | Escalation matrix; `disclosure.md` |
| | Analysis | Audit + WORM evidence — root-cause traceable |
| | Mitigation | Denylist, rate-limit overrides, circuit breakers |
| | Improvements | ADR process; post-incident review captured in audit history |
| **Recover** (RC) | Recovery planning | DB backup (operator), Helm re-install, PDB |
| | Improvements | CHANGELOG + ADR feedback loop |
| | Communications | `SECURITY.md`, status-page (gap — checklist 10.5) |

### 6. AI Act (EU) — preliminary mapping

| Article | Requirement | VG position |
|---|---|---|
| Art. 9 | Risk management for high-risk AI | Threat model; downstream consumer responsibility |
| Art. 10 | Data and data governance | Input-hash rule; no raw retention by default |
| Art. 12 | Record-keeping (logs) | Audit + CITADEL WORM evidence |
| Art. 14 | Human oversight | Confidence is a contract; operator-set thresholds; appeal via WORM record |
| Art. 15 | Accuracy, robustness, cybersecurity | Adversarial test corpus; pattern refresh cadence |

Detailed mapping: `docs/nis2-ai-act-mapping.md`.

### 7. Gap summary

| Framework | Open gap | Tracked in |
|---|---|---|
| NIS2 supply-chain | govulncheck / cargo audit in CI | checklist 7.4 / 7.5 |
| OWASP A05 / A08 | NetworkPolicy default-on, cosign signing | checklist 6.7 / 6.13 |
| OWASP A07 | Refuse-to-start when dev_mode in prod | checklist 2.10 |
| NIST CSF Recover/Communications | Public status page | checklist 10.5 |

All open gaps are scoped Small or Medium and fit inside the T-6
window in `pre-audit-plan.md`.
