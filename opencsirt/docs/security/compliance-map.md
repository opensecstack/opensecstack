# OpenCSIRT Compliance Traceability Matrix

> Maps OpenCSIRT controls to the frameworks an EU NIS2-scope auditor
> will reference. Evidence cites repository paths so each row can be
> verified against the source of truth. Companion to
> [threat-model.md](threat-model.md) and
> [security-checklist.md](security-checklist.md).
>
> **OpenCSIRT is the implementation of NIS2 Article 11** — the
> national CSIRT mandate. That is the strategic spine of this
> document; the rest of the matrix is supporting evidence.

## 1. NIS2 Article 11 — National CSIRT mandate

Article 11(3) lists the CSIRT's tasks. OpenCSIRT is the platform
that operationalises them.

| Article 11(3) sub-point | Requirement | OpenCSIRT implementation | Gap |
|---|---|---|:-:|
| **(a)** | Monitor and analyse cyber threats, vulnerabilities, and incidents at national level | `incidents` table; `ioc_ingest_log` from ThreatFlow puller (see [../threatflow-integration.md](../threatflow-integration.md)); VertGuard subscriber (see [../vertguard-integration.md](../vertguard-integration.md)) | N |
| **(b)** | Provide early warning, alerts, announcements, and information dissemination | `advisories` table with CSAF 2.0 documents; publish endpoint (csirt_lead+); ThreatFlow advisory push closes the IOC loop | N |
| **(c)** | Respond to incidents and provide assistance | `incidents` lifecycle (open → triaged → contained → closed); IRFlow webhook ingest at `/api/v1/integrations/irflow/incident`; CITADEL `opencsirt.incident_opened`/`_closed` events | N |
| **(d)** | Perform dynamic risk and incident analysis and situational awareness | metrics, `ioc_ingest_log` aggregations, abuse-mailbox parser feeding the Python advisory subsystem on `:8089` | N |
| **(e)** | Participate in the CSIRTs network | `peer_csirts` table; `escalations` table; `opencsirt.escalation_sent` CITADEL event | N |
| **(f)** | Cooperate with private sector | constituency model (`constituencies` table with `nis2_status` ∈ `essential`/`important`/`out_of_scope`); per-constituency advisory dissemination | N |
| **(g)** | Promote standardised practices for incident handling and response | CSAF 2.0 advisory format; STIX 2.1 IOC bundles; FIRST.org Service Framework v2 alignment (§4 below) | N |

The CSIRT also participates upstream:

- **Article 11(4)** (cooperation with national authorities) — the
  outbound NIS2 Compass channel (see [../nis2-integration.md](../nis2-integration.md)).
- **Article 11(5)** (cross-border cooperation) — the peer CSIRT
  registry + escalation flow.

## 2. NIS2 Article 23 — Incident reporting

Operators of essential and important entities must notify the CSIRT
within 24 hours (early warning) and 72 hours (incident notification).
OpenCSIRT does **not** call competent authorities directly — it
records the incident and notifies NIS2 Compass, which holds the
deadline timers.

| Output | Consumer | Pathway |
|---|---|---|
| Incident open at severity ≥ HIGH | NIS2 Compass | `(*NIS2Client).Notify` POSTs `/api/v1/notifications/article23` (see [../nis2-integration.md](../nis2-integration.md)); Compass starts the 24h/72h clock |
| `opencsirt.incident_opened` / `_closed` CITADEL events | CITADEL WORM | auditor verifies the timeline against the Ed25519-anchored chain |
| Advisory publication | ThreatFlow + constituency | CSAF 2.0 push (see [../threatflow-integration.md](../threatflow-integration.md)) |

The 24h/72h deadlines themselves are owned by NIS2 Compass, not by
OpenCSIRT — same pattern as the rest of the ecosystem.

## 3. NIS2 Article 21(2) — Security risk-management measures

OpenCSIRT is **not** the operator-side implementation of Article
21(2) — it is the CSIRT-side platform. But several Article 21(2)
measures get evidence from OpenCSIRT outputs:

| Measure | Title | OpenCSIRT contribution | Notes |
|---|---|---|---|
| (a) | Risk-analysis & info-system security policies | [threat-model.md](threat-model.md); operator's own ISMS | Deployer responsibility |
| (b) | Incident handling | OpenCSIRT incident lifecycle; IRFlow inbound; CITADEL events | Operator-side incident management lives in IRFlow |
| **(c)** | **Business continuity** (incl. backup, DR, crisis mgmt) | **ThreatFlow IOC consumption** keeps the operator's mitigation-feed populated; **advisory dissemination** to the constituency keeps essential entities aware of active threats. Both are continuity-of-operations enablers. | Primary OpenCSIRT contribution to Article 21(2) |
| (d) | Supply-chain security | `ioc_ingest_log` lineage; CSAF advisories include vendor + version | — |
| (e) | Acquisition / dev / maintenance security | 2-reviewer rule on advisory templates; semgrep `no raw sql`; OpenAPI contract as source-of-truth | — |
| (f) | Effectiveness assessment | Prometheus metrics + NIS2 Compass evidence | Assessment surface is NIS2 Compass |
| **(g)** | **Cyber hygiene + training** | **Out of scope — CyberPath covers it.** OpenCSIRT advisories may *reference* training material but the audit-grade training-evidence source is [../../../cyberpath/](../../../cyberpath/) | Pointer-only |
| (h) | Cryptography & encryption | HMAC-SHA256 on CITADEL emit + IRFlow webhook (see [../citadel-integration.md](../citadel-integration.md)); JWT HS256; TLS at ingress | — |
| (i) | HR security & access control | 6-role RBAC ([`internal/auth/auth.go`](../../internal/auth/auth.go)); `csirt_lead`-only publish; admin-only peer-registry mutations | — |
| (j) | MFA / continuous auth / secure comms | Operator-side IdP fronts OpenCSIRT; deferred to deployer | Y |

## 4. CSIRT operational standards

### 4.1 FIRST.org Service Framework v2 mapping

The FIRST.org CSIRT Services Framework v2.1 lists the canonical
service areas a CSIRT delivers. OpenCSIRT covers them as follows:

| Service area | OpenCSIRT support |
|---|---|
| **Information Security Event Management** | `incidents` table; abuse-mailbox parser (`:8089`); IRFlow inbound; VertGuard subscriber |
| **Information Security Incident Management** | incident lifecycle; CITADEL evidence chain; peer escalation; constituency metadata |
| **Vulnerability Management** | CSAF 2.0 advisories; ThreatFlow round-trip |
| **Situational Awareness** | metrics; `ioc_ingest_log`; constituency-grouped views |
| **Knowledge Transfer** | advisories carry remediation guidance; CyberPath linkage for operator training |

The framework is operational, not regulatory — but auditors familiar
with mature CSIRTs will reference it; the mapping above is the
quick answer.

### 4.2 ENISA CSIRT Maturity baseline

ENISA's CSIRT Maturity Framework defines three tiers (Basic /
Intermediate / Advanced) across SIM3-aligned dimensions
(Organisational, Human, Tools, Processes). OpenCSIRT v1.0.0 hits
the **Intermediate** baseline:

| SIM3 dimension | v1.0.0 posture |
|---|---|
| Organisational | Constituency model + peer registry; admin/csirt_lead/operator separation |
| Human | 6-role RBAC; security-checklist requires named role assignments |
| Tools | OpenCSIRT itself + ThreatFlow + CITADEL + IRFlow + NIS2 Compass — full ecosystem stack |
| Processes | Documented in [../advisory-authoring-guide.md](../advisory-authoring-guide.md), [../peer-csirt-handshake-protocol.md](../peer-csirt-handshake-protocol.md), and the [security/](.) docset |

Advanced tier requires 24/7 staffing and a published constituency
SLA — both are operator-side, not platform-side, so the platform
is Advanced-ready but the certification depends on the deploying
organisation.

## 5. AI Act (EU) 2024/1689 — applicability

OpenCSIRT itself is **not in scope** of the EU AI Act:

- It does not deploy a general-purpose AI model.
- Its primary functions (incident records, advisories, peer
  coordination, evidence emission) are not high-risk AI systems
  under Annex III.
- It does not perform biometric identification, social scoring, or
  any prohibited practice in Article 5.

The VertGuard subscriber consumes AI-attack-defence advisories (see
[../vertguard-integration.md](../vertguard-integration.md)) but
OpenCSIRT only stores the metadata; the AI inference is on the
VertGuard side.

## 6. GDPR Article 32 — Security of processing

OpenCSIRT processes minimal PII — operator JWT subject, abuse-mail
sender addresses, constituency contact emails.

| Requirement | OpenCSIRT implementation |
|---|---|
| Pseudonymisation | abuse-mail sender stored only as needed for dedup; PII-minimisation note in advisory authoring guide |
| Encryption | TLS at ingress; `sslmode=require` on Postgres; HMAC-SHA256 on outbound |
| Confidentiality of processing | RBAC; metrics endpoint firewalled in prod |
| Integrity of processing | CITADEL WORM mirror; append-only `audit_log` |
| Availability + resilience | Outbox + retry buffer; bounded staleness on CITADEL |
| Restoration after incident | DB backup (operator); Helm re-install |
| Regular testing | [pre-audit-plan.md](pre-audit-plan.md); pentest before v1.0.0 audit |
| Risk-appropriate measures | Threat model documents proportionality; TLP:RED-leak findings get tightest SLA |

## 7. ISO/IEC 27001:2022 — control families touched

| Annex A family | OpenCSIRT touchpoint |
|---|---|
| A.5 (Organisational) | [../../SECURITY.md](../../SECURITY.md), this docset |
| A.8 (Asset management) | OpenAPI surface, SBOM at release |
| A.9 (Access control) | 6-role RBAC, `RequireRole` middleware |
| A.12 (Operations security) | `audit_log`, structured logs (zerolog), Prometheus metrics |
| A.14 (Acquisition / dev / maintenance) | 2-reviewer rule; semgrep / govulncheck in CI |
| A.16 (Incident management) | incident lifecycle; IRFlow integration; runbook |
| A.17 (Business continuity) | CITADEL outbox + retry; advisory dissemination keeps constituency aware |

OpenCSIRT does not claim ISO 27001 certification of itself; it
provides controls a deployer can use within their own ISMS.

## 8. AGPL-3.0 licensing note

OpenCSIRT is published under AGPL-3.0 — the same licence as
CITADEL, IRFlow, NIS2 Compass, and VertGuard. Deployer
modifications that touch governance functionality must remain open
upstream. See
[../../../ECOSYSTEM.md § Licensing Model](../../../ECOSYSTEM.md#licensing-model).

## 9. Gap summary

| Framework | Open gap | Tracked in |
|---|---|---|
| NIS2 21(2)(j) | MFA on operator login (delegated to upstream IdP) | Not a code-level gap |
| ENISA Advanced tier | 24/7 staffing + published SLA | Operator-side, not platform-side |
| AI Act borderline | None — no AI inference in OpenCSIRT itself | — |

All open gaps are scoped Small or formally accepted as v1.x roadmap.

## 10. Related

- [threat-model.md](threat-model.md)
- [security-checklist.md](security-checklist.md) — control evidence
- [pentest-scope.md](pentest-scope.md)
- [pre-audit-plan.md](pre-audit-plan.md)
- [../citadel-integration.md](../citadel-integration.md)
- [../irflow-integration.md](../irflow-integration.md)
- [../threatflow-integration.md](../threatflow-integration.md)
- [../nis2-integration.md](../nis2-integration.md)
- [../vertguard-integration.md](../vertguard-integration.md)
- [../../SECURITY.md](../../SECURITY.md)
- [../../../openscrub/docs/security/compliance-map.md](../../../openscrub/docs/security/compliance-map.md) — sibling reference
