# OpenScrub Compliance Traceability Matrix

> Maps OpenScrub controls to the frameworks an EU NIS2-scope auditor
> will reference. Evidence cites repository paths so each row can be
> verified against the source of truth. Companion to
> [threat-model.md](threat-model.md) and
> [security-checklist.md](security-checklist.md).

OpenScrub's primary regulatory hook is **NIS2 Article 21(2)(c)** —
business continuity and incident handling. DDoS mitigation at NIC
ingress is the load-bearing control for that measure in deployments
where OpenScrub is deployed; **Article 21(2)(d)** (supply-chain
security) is the secondary hook because OpenScrub's blocklist is
populated from a vendor IOC feed (ThreatFlow). Article 23 (incident
notification) flows through the IRFlow integration. Article 21(2)(g)
(training) is tangential — pointers to CyberPath cover that.

### 1. NIS2 (Directive (EU) 2022/2555) — Article 21(2)

| Measure | Title | Requirement | OpenScrub implementation | Gap | Notes |
|---|---|---|---|:-:|---|
| (a) | Risk analysis & info-system security policies | Policies for risk analysis and security of information systems | [threat-model.md](threat-model.md) (STRIDE for kernel surface); operator runs OpenScrub under their own ISMS | N | Deployer responsibility for org-level ISMS |
| (b) | Incident handling | Detect, handle, and report incidents | Live mitigation feed at `/api/v1/mitigations`; CITADEL `openscrub.mitigation` events; sustained-mitigation IRFlow webhook (see [../irflow-integration.md](../irflow-integration.md)) | N | Notification automation is operator-side via IRFlow + NIS2 Compass |
| (c) | **Business continuity** (incl. backup, DR, crisis mgmt) | Maintain availability under attack | **Primary OpenScrub driver.** XDP `XDP_DROP` at NIC ingress preserves application availability under L3/L4 DDoS; per-CIDR rate-limit map; data plane runs unaffected by API outage (existing maps continue to drop) | N | Volumetric attacks past NIC line rate are out of architectural scope (upstream BGP scrubbing partner) |
| (d) | **Supply-chain security** | Supplier risk; dependencies | `go.sum`, `Cargo.lock`, `package-lock.json`, image SHA-256 + Cosign signatures, SBOM (CycloneDX) at release; **ThreatFlow IOC feed is treated as a supply-chain input** — per-bundle SHA logged in `ioc_ingest_log`, allowlist guard prevents operator-CIDR poisoning, max-delta-per-pull cycle aborts on > 50% churn (see [../threatflow-integration.md](../threatflow-integration.md)) | N | govulncheck / cargo audit / npm audit wired in CI per [security-checklist.md § 8](security-checklist.md) |
| (e) | Acquisition / dev / maintenance security | Security in sys acquisition, development, maintenance | 2-reviewer rule on data-plane changes (CODEOWNERS for `ebpf/` and `rust/dataplane/`); semgrep `no raw sql` rule; OpenAPI contract as source-of-truth | N | — |
| (f) | Effectiveness assessment | Procedures for assessing effectiveness | Prometheus metrics (`pps_dropped`, `pps_passed`, `rules_active`, `ioc_pull_latency_ms`) feed NIS2 Compass which performs assessment; OpenScrub records the input | N | Assessment surface is NIS2 Compass, not OpenScrub |
| (g) | Cyber hygiene + training | Basic cyber hygiene practices and cybersecurity training | **Tangential** — OpenScrub is an enforcement plane, not a training plane. Pointer to [../../cyberpath/](../../cyberpath/) which is the audit-grade training-evidence source | N | Operators of OpenScrub are expected to complete CyberPath Track 7 (Linux hardening) and Track 8 (Network forensics) |
| (h) | Cryptography & encryption | Policies on cryptography use | HMAC-SHA256 on CITADEL emit and IRFlow webhook; JWT HS256 (configurable to RS256); TLS at ingress; secrets never logged | N | Same primitives as the rest of the ecosystem; rotation cadence in [security-checklist.md § 4](security-checklist.md) |
| (i) | HR security & access control | Identity, RBAC, training awareness | opensecstack/sdk auth + RBAC (viewer / operator / admin); CITADEL Gate-3 NDS for cross-author/approver separation on dangerous rules | N | Single-tenant in v1.0.0; multi-tenant arrives in Phase 2.1+ |
| (j) | MFA / continuous auth / secure comms | Use of MFA, continuous auth, secure comms | TLS at ingress; MFA-on-login deferred to ecosystem SSO integration (operator brings their own IdP) | Y | Tracked under residual risk; production deployments are expected to front OpenScrub with an MFA-capable IdP |

### 2. NIS2 Article 23 — incident notification

OpenScrub does not call competent authorities directly. It produces
two things an operator's notification pipeline consumes:

| Output | Consumer | Pathway |
|---|---|---|
| `openscrub.mitigation` CITADEL events | NIS2 Compass | Compass queries CITADEL WORM for evidence under Article 23 24h-initial / 72h-notification timers |
| Sustained-mitigation IRFlow webhook | IRFlow → NIS2 Compass | A mitigation row with `started_at < now() - interval '5 minutes'` AND `ended_at IS NULL` triggers an IRFlow `incident.create`. IRFlow then runs the operator's notification playbook. See [../irflow-integration.md](../irflow-integration.md) |

The 24h/72h notification timers themselves are owned by the
operator's SOC tooling, not by OpenScrub.

### 3. AI Act (EU) 2024/1689 — applicability

OpenScrub is **not in scope** of the EU AI Act:

- It does not deploy a general-purpose AI model.
- Its primary functions (XDP packet filtering, rule CRUD, IOC reconciliation, evidence emission) are not high-risk AI systems under Annex III.
- It does not perform biometric identification, social scoring, or any of the prohibited practices in Article 5.

| Article | Requirement | OpenScrub position |
|---|---|---|
| Art. 5 | Prohibited AI practices | N/A — none used |
| Art. 6 + Annex III | High-risk AI systems | N/A — OpenScrub is a deterministic packet filter, not an AI system |
| Art. 50 | Transparency obligations | N/A — OpenScrub does not generate synthetic content or interact with users as an AI |

If a future iteration introduces ML-based DDoS classification (e.g.,
flow-feature anomaly scoring), AI-Act applicability re-review is
required. Tracked as a v2.x design constraint, not present in v1.0.0.

### 4. GDPR Article 32 — Security of processing

OpenScrub processes minimal PII — operator JWT subject and source IP
addresses on the mitigations table.

| Requirement | OpenScrub implementation | Evidence |
|---|---|---|
| Pseudonymisation | Source IPs persisted on `mitigations` rows are not joined to identity; operator JWT subject is the only identifier in audit | `migrations/0001_init.up.sql` |
| Encryption | TLS at ingress; `ssl_mode=require` on Postgres; HMAC-SHA256 on outbound | [security-checklist.md § 6, § 8](security-checklist.md) |
| Confidentiality of processing | RBAC scopes; metrics endpoint firewalled in prod | [security-checklist.md § 5, § 7](security-checklist.md) |
| Integrity of processing | CITADEL WORM mirror for `openscrub.mitigation` and `openscrub.rule_change`; append-only audit_log | [../citadel-integration.md](../citadel-integration.md) |
| Availability + resilience | Data plane unaffected by API outage; bounded outbox for CITADEL with WAL-style overflow drop | [threat-model.md § STRIDE row #7](threat-model.md), [../citadel-integration.md § Delivery semantics](../citadel-integration.md) |
| Restoration after incident | DB backup (operator); Helm re-install; data plane stateless beyond rules table | operator handbook |
| Regular testing | [pre-audit-plan.md](pre-audit-plan.md); pentest before v1.0.0 audit; quarterly threat-model review | [pre-audit-plan.md](pre-audit-plan.md) |
| Risk-appropriate measures | Threat model documents proportionality; kernel-tier findings get tightest SLA | [threat-model.md](threat-model.md), [../../SECURITY.md](../../SECURITY.md) |

Source-IP retention is operator-policy: defaults to 30 days on the
mitigations table. Right-to-erasure (Art. 17) on operator JWT subject
is handled by SSO de-provisioning; mitigation rows are not joinable
to identity.

### 5. ISO/IEC 27001:2022 — control families touched

| Annex A family | Title | OpenScrub touchpoint |
|---|---|---|
| A.5 | Organisational policies | [../../SECURITY.md](../../SECURITY.md), this document set |
| A.8 | Asset management | Helm `values.yaml`, OpenAPI surface (`api/openapi.yaml`), SBOM at release |
| A.9 | Access control | opensecstack/sdk auth, RBAC, CITADEL Gate-3 NDS |
| A.12 | Operations security | Audit table, structured logs (zerolog), Prometheus metrics |
| A.14 | System acquisition, development, maintenance | 2-reviewer rule on data-plane changes; semgrep / clippy / eslint in CI |
| A.16 | Information security incident management | [../../SECURITY.md](../../SECURITY.md), IRFlow integration, operator runbook |
| A.17 | Business continuity | Data plane unaffected by control-plane outage; CITADEL outbox with overflow drop |

OpenScrub does not claim ISO 27001 certification of itself; it
provides controls a deployer can use within their own ISMS.

### 6. Apache 2.0 licensing note

OpenScrub is published under Apache-2.0, the same licence as
APIGuard / ThreatFlow / CyberPath / SecureLab. Deployers can fork
and embed in proprietary edge stacks (see
[../../../ECOSYSTEM.md § Licensing Model](../../../ECOSYSTEM.md#licensing-model)).
Compliance-relevant points:

- Apache 2.0 grants a patent licence covering the platform as it ships.
- Forks that add new mitigation logic grant the same patent terms back upstream when contributed.
- Attribution (NOTICE file) must survive forks; an auditor verifying provenance can trace it back to the upstream commit.

### 7. Gap summary

| Framework | Open gap | Tracked in |
|---|---|---|
| NIS2 (j) | MFA on operator login (delegated to upstream IdP) | Operator deploys an MFA-capable IdP in front of OpenScrub; not a code-level gap |
| AI Act borderline | ML-based flow classification | v2.x design constraint, no current code |

All open gaps are scoped Small or formally accepted as v1.x roadmap.

### 8. Related

- [threat-model.md](threat-model.md)
- [security-checklist.md](security-checklist.md) — gap inventory
- [pentest-scope.md](pentest-scope.md)
- [pre-audit-plan.md](pre-audit-plan.md)
- [../citadel-integration.md](../citadel-integration.md)
- [../irflow-integration.md](../irflow-integration.md)
- [../threatflow-integration.md](../threatflow-integration.md)
- [../../SECURITY.md](../../SECURITY.md)
- cyberpath/docs/security/compliance-map.md (see `cyberpath/docs/security/compliance-map.md`) — sibling reference
