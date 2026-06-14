# VertGuard — NIS2 & EU AI Act Mapping

VertGuard sits at the intersection of two EU regulatory regimes that
both apply to NIS-scope organisations in 2026+:

- **NIS2 Directive 2022/2555** — cybersecurity risk management, Art. 21
  measures + Art. 23 incident notification. In force since Oct 2024.
- **EU AI Act (Regulation 2024/1689)** — governance of AI systems. Risk
  categories, transparency, human oversight. Entered force Aug 2024
  with staggered applicability through 2027.

This document maps VertGuard features onto obligations from both so
operators and auditors can trace controls to compliance.

For ecosystem-wide NIS2 mapping (all 10 platforms), see
[../../nis2compass/docs/nis2-controls-reference.md](../../nis2compass/docs/nis2-controls-reference.md).

## NIS2 Article 21 — risk management measures

| Measure | Title | VertGuard contribution |
|---|---|---|
| **(a)** | Risk analysis & security policies | AI-attack detection patterns encode AI-threat response policy in runnable form |
| **(b)** | Incident handling | AI-attack detections auto-create IRFlow incidents; every detection is WORM-logged |
| **(c)** | Business continuity | Not primary; indirect via IRFlow incident workflow |
| **(d)** | Supply chain security | Model registry + SHA-256 checksums = supply chain evidence for ML dependencies |
| **(e)** | Network & info systems security | **Primary** — VertGuard is specifically AI-attack defence for network/IT systems |
| **(f)** | Effectiveness assessment | Metrics export (`vertguard_prompt_blocked_total{category}`) feeds compliance review |
| **(g)** | Cyber hygiene & training | Not primary; CyberPath (planned Phase 2) covers this |
| **(h)** | Cryptography | HMAC-SHA256 webhooks, TripleHash evidence, post-quantum roadmap |
| **(i)** | HR security & access control | RBAC inherited from ecosystem; SoD via CITADEL integration |
| **(j)** | MFA & secure communications | TLS terminates at ingress; MFA at upstream IdP |

**Primary measure:** (e) — VertGuard is specifically designed as an
AI-attack defence for network and information systems.

**Secondary contributions:** (b), (d), (h) — incident handling via
IRFlow integration, supply chain evidence via model registry,
cryptographic evidence via TripleHash and post-quantum strategy.

## NIS2 Article 23 — incident notification

AI-attack detections can trigger Article 23 notifications if the
incident meets "significant incident" thresholds:

| Threshold | VertGuard evidence |
|---|---|
| Service continuity disruption | Detections that preceded outages are WORM-linked |
| Data breach / confidentiality | LLM06 exfil attempts, synthetic identity fraud |
| Financial impact > €500k | Voice-clone CEO fraud, synthetic-identity wire fraud |
| Cross-border impact | Attacks originating outside local jurisdiction |

When a detection rises to Article 23 scope, IRFlow auto-initiates the
72-hour notification workflow through NIS2 Compass. VertGuard's role
is to provide:

- WORM-anchored evidence of the detection
- Timestamp within the 24-hour early-warning window
- MITRE ATLAS categorisation (for regulator context)
- Severity classification

## EU AI Act — applicability to VertGuard

The AI Act applies to VertGuard in **two ways**:

### 1. VertGuard as AI system provider (low-risk tier)

VertGuard itself uses ML for Modules 1, 2, 5 (Phase 4.2+). Per the
Act, this makes VertGuard an AI system operator with obligations:

| Obligation | VertGuard compliance |
|---|---|
| Risk management (Art. 9) | Documented in SECURITY.md threat model |
| Data governance (Art. 10) | Model + dataset registries with provenance |
| Technical documentation (Art. 11) | Full model cards in `docs/ml-models-reference.md` |
| Record keeping (Art. 12) | All detections WORM-logged via CITADEL |
| Transparency (Art. 13) | Per-detection confidence exposed; deterministic patterns separated from ML classification |
| Human oversight (Art. 14) | Appeals process via CITADEL; operators can override classifications |
| Accuracy (Art. 15) | Published accuracy benchmarks; false-positive test corpus |
| Cybersecurity (Art. 15) | ← VertGuard is itself cybersecurity; self-hosted deployment supports this |

### 2. VertGuard as defence for AI system operators

Organisations deploying LLM-powered applications are themselves
AI Act-scoped. VertGuard provides the **technical controls** they
need for:

- **Transparency evidence** — detection logs show what the AI system
  was instructed to do
- **Human oversight implementation** — prompt-injection blocking is
  a mandated oversight control
- **Accuracy support** — detections flag likely unreliable inputs
  before they corrupt the model's outputs
- **Cybersecurity compliance** — AI-attack defence is an explicit
  Art. 15 requirement

## Control mapping summary

| Control objective | Regulation | VertGuard feature |
|---|---|---|
| Detect AI-driven attacks | NIS2 Art. 21(e) | Modules 3, 4 (Phase 4.1) + 1, 2, 5 (later) |
| Record AI security events | NIS2 Art. 21(b) + AI Act Art. 12 | CITADEL WORM integration |
| Maintain AI supply chain provenance | NIS2 Art. 21(d) + AI Act Art. 10 | Model/dataset registries with SHA-256 |
| Notify regulators of significant incidents | NIS2 Art. 23 | IRFlow integration → NIS2 Compass |
| Human oversight of LLM applications | AI Act Art. 14 | Module 3 blocking + appeal flow |
| Transparency of detection logic | AI Act Art. 13 | Deterministic patterns published; ML confidence exposed |
| Post-quantum migration path | NIS3 (projected 2030-2032) | Inherited from ecosystem PQ roadmap |

## Evidence packaging for auditors

For an NIS2 or AI Act audit, VertGuard exports:

```bash
vertguard evidence export \
  --from 2026-01-01 \
  --to 2026-12-31 \
  --format audit-bundle \
  --output /tmp/vertguard-evidence-2026.tar.gz
```

Bundle contents:

- **manifest.yaml** — custody chain (who authorised export, who received)
- **detections.jsonl** — every detection in range
- **worm-references.jsonl** — CITADEL WORM entry IDs for cross-verification
- **model-versions.yaml** — which ML models were active on each date
- **pattern-versions.yaml** — pattern-library version history
- **atlas-mappings.yaml** — MITRE ATLAS versions referenced
- **metrics-summary.json** — aggregate metrics (total scans, blocked rate, FP rate)

Auditors can cross-verify WORM entries against the CITADEL chain
independently.

## Differentiator vs commercial alternatives

Commercial AI-defence tools (Reality Defender, Lakera, Protect AI):

- ✅ Detect AI attacks
- ❌ No WORM audit chain (logs in vendor's cloud, not deployer-owned)
- ❌ No formal NIS2 / AI Act control mapping
- ❌ SaaS-only: data leaves jurisdiction (GDPR + sovereignty concerns)
- ❌ No regulator-auditable evidence export

VertGuard:

- ✅ Detect AI attacks
- ✅ WORM audit chain (deployer-owned via CITADEL)
- ✅ Formal NIS2 + AI Act mapping (this document)
- ✅ Self-hostable: data stays in jurisdiction
- ✅ Regulator-auditable evidence export

This is the **NIS-scope positioning**: organisations that cannot
accept SaaS AI-defence for regulatory reasons (healthcare, banking,
public admin, critical infrastructure) gain an OSS alternative.

## NIS3 forward-looking

NIS3 (expected 2030-2032) is projected to include:

- AI-attack defence as explicit obligation
- Post-quantum migration mandate
- Cross-CSIRT AI-threat sharing requirements
- Evidence retention extensions for AI-related incidents

VertGuard is designed to become the **NIS3 reference tool** for
these obligations. See [nis3-readiness.md](nis3-readiness.md) for the
positioning strategy.

## Related

- [../../nis2compass/docs/nis2-controls-reference.md](../../nis2compass/docs/nis2-controls-reference.md) — full NIS2 framework
- [../../docs/security-maturity.md](../../docs/security-maturity.md) — deployment tiers
- [nis3-readiness.md](nis3-readiness.md)
- [citadel-integration.md](citadel-integration.md)
- [EU AI Act consolidated text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)
