# NIS3 Readiness Statement

**Document status:** Living document — updated as NIS3 drafts progress.
**Current VertGuard version:** v0.1.x (Phase 4.1)
**NIS3 expected ratification:** 2030-2032 (Commission review required by Oct 2027 per NIS2 Art. 41)

For current NIS2 + EU AI Act mapping, see [nis2-ai-act-mapping.md](nis2-ai-act-mapping.md).
For ecosystem-wide NIS2 mapping, see [../../nis2compass/docs/nis2-controls-reference.md](../../nis2compass/docs/nis2-controls-reference.md).

---

## 1. Executive Summary

NIS2 (Directive 2022/2555) is the current cybersecurity risk-management baseline for essential
and important entities across the EU. NIS3 — its projected successor — does not yet exist as
a formal instrument. Based on Article 41's review schedule, the Commission will publish a
review by October 2027; a legislative proposal is plausible for 2028-2029, with adoption
2030-2031 and transposition 2032-2033.

NIS3 is expected to move beyond NIS2's generic "network and information systems security"
language and introduce explicit obligations for AI-system attack defence, AI supply-chain
provenance, cross-CSIRT AI-threat sharing, and post-quantum cryptographic migration.

**VertGuard's posture today (May 2026):**

- Modules 3 (prompt injection) and 4 (AI threat feed) are in active development at v0.1.
- Module 1 (media authenticity via C2PA) is Phase 4.1 partial.
- Modules 2 (AI phishing) and 5 (synthetic identity) are scaffolded for Phase 4.2/4.3.
- CITADEL WORM integration provides tamper-evident evidence retention from day one.
- The platform is designed to become the OSS reference implementation for AI-attack-defence
  obligations under NIS3, based on deployment history accumulated from v0.1 onward.

Deployers in 2026 are not "NIS3-compliant" — NIS3 does not exist. They are
**NIS2 Article 21(e)-aligned** and accumulating the evidence chain that NIS3 will require.

---

## 2. NIS3 Proposed Requirements vs VertGuard Capabilities

The table below maps projected NIS3 obligation areas onto current VertGuard capabilities.
Projections are based on NIS2 review signals, ENISA preparatory studies, and EU AI Act
trajectory. Status markers: **Covered** (capability exists today), **Partial** (foundation
present, gaps remain), **Planned** (on roadmap, not yet implemented), **Gap** (no current
coverage).

| NIS3 projected requirement | Obligation basis | VertGuard capability today | Status |
|---|---|---|---|
| AI-system input attack defence (prompt injection, jailbreaks) | NIS2 Art. 21(e) extension | Module 3 — pattern + ML classifier (Phase 4.1/4.2) | **Covered** |
| Deepfake / synthetic media detection | NIS3 signal: AI-content authenticity | Module 1 — C2PA in v0.1; ML deepfake in v0.5 | **Partial** |
| AI-generated phishing detection | NIS3 signal: AI-enabled social engineering | Module 2 — planned v0.5 (2027 Q3) | **Planned** |
| Synthetic identity detection in KYC | NIS3 signal: AI-fraud prevention | Module 5 — planned v1.0 (2028 Q3) | **Planned** |
| ML supply-chain provenance (model + dataset) | NIS2 Art. 21(d) extension | Model registry + SHA-256 checksums; dataset registry | **Partial** |
| Signed ML model manifests (SBOM-equivalent) | NIS3 signal: AI supply chain | Planned v1.1 (signed model cards) | **Planned** |
| AI-specific incident evidence retention (7+ years) | NIS3 signal: evidence for AI incidents | CITADEL WORM from v0.1; retention window operator-configured | **Partial** |
| Cryptographic evidence chain (tamper-evident) | NIS2 Art. 21(h) extension | TripleHash + CITADEL WORM + anchor signatures | **Covered** |
| Cross-CSIRT AI-threat indicator sharing | NIS2 Art. 29 extension | Module 4 MITRE ATLAS-tagged IOCs via ThreatFlow STIX bundle | **Partial** |
| Standardised AI-IOC format (STIX + MITRE ATLAS) | NIS3 signal: interoperability | ThreatFlow STIX-compatible bundle; ATLAS tagging | **Covered** |
| Cross-border CSIRT federation | NIS3 signal: federation | OpenCSIRT integration — Phase 3, not yet implemented | **Planned** |
| Post-quantum cryptographic migration | ENISA/BSI/ANSSI signal: PQC mandate 2028-2030 | Ecosystem PQ roadmap; v3.0 PQ-default (2030) | **Planned** |
| AI-agent governance (human oversight, audit trail) | EU AI Act Art. 14 + NIS3 projection | CITADEL MARSHAL gate; every action reviewable | **Partial** |
| Auditor self-service evidence access | NIS3 signal: regulator access | Evidence export bundle; auditor cross-verify via CITADEL | **Partial** |
| Vulnerability disclosure programme | NIS2 Art. 21 + NIS3 extension | Coordinated disclosure via SECURITY.md; 90-day window | **Covered** |
| Third-party security audit | NIS3 signal: independent assurance | Formal audit planned pre-v1.0 (2028 target) | **Planned** |

---

## 3. Gaps vs NIS2: What NIS3 Adds

NIS2 Art. 21 covers generic risk management, incident handling, supply-chain security,
cryptography, and access control. NIS3 is projected to introduce obligations that go beyond
current NIS2 scope in the following areas:

| Area | NIS2 position | NIS3 addition (projected) |
|---|---|---|
| AI-attack defence | Implicit under Art. 21(e) "network and info systems security" | Explicit obligation: named AI-attack categories (prompt injection, deepfakes, AI phishing) |
| AI supply chain | Art. 21(d) covers ICT products/services generically | Explicit: ML model and dataset provenance, signed manifests, SBOM-equivalent for AI artefacts |
| Incident reporting scope | Art. 23: significant incidents to national CSIRT | Extended: AI-specific incident categories; mandatory AI-IOC reporting to CSIRT |
| Retention period | Not specified for AI events | Projected 7-year minimum for AI-related incident evidence |
| IOC format | Art. 29: information sharing, format unspecified | Standardised AI-IOC format (STIX + MITRE ATLAS); cross-border federation requirements |
| Cryptographic migration | Art. 21(h): cryptography, algorithm-agnostic | Explicit PQC migration mandate with cut-off dates (BSI/ANSSI alignment) |
| AI-agent governance | Not addressed | Mandatory: every AI-initiated action human-reviewable; AI-agent identity verifiable |
| Third-party audit | Implied by Art. 21 effectiveness assessment | Explicit: periodic third-party audits for AI systems in scope |
| Vulnerability disclosure | Art. 21 + ENISA guidance | Formalised coordinated vulnerability disclosure with regulator notification |

---

## 4. VertGuard-Specific Readiness by Module

### Module 1 — Media Authenticity (C2PA provenance → supply-chain security)

C2PA manifest verification is a direct supply-chain integrity control. Each verified media
asset carries a cryptographic signer chain traceable to a trusted CA (Adobe, Microsoft, BBC,
Google). The `c2pa-verify` Rust binary validates the full manifest, and VertGuard records the
outcome in the CITADEL WORM chain, producing tamper-evident provenance evidence.

**NIS3 relevance:** AI supply-chain provenance extends naturally to media provenance.
C2PA-signed content satisfies the "verifiable origin" requirement projected for NIS3 AI
supply-chain obligations. Gap: real-time video deepfake detection (Module 1 ML, Phase 4.2)
is not yet available; static images and audio only.

**EU AI Act overlap:** Art. 10 (data governance), Art. 13 (transparency — signer chain
exposed per detection), Art. 15 (robustness — tamper-evident provenance).

### Module 3 — Prompt Injection Defence (AI risk management)

Module 3 is the primary AI risk management control. It intercepts inputs to LLM applications
before they reach the model, classifying and blocking injection attempts, jailbreaks, indirect
injection, and instruction overrides. In Phase 4.1 the classifier is pattern-based; Phase 4.2
adds a DistilBERT-based ML classifier with published accuracy benchmarks and a false-positive
appeal flow.

**NIS3 relevance:** NIS3 is projected to name prompt injection defence as an explicit
obligation for operators of LLM-powered services. Module 3 satisfies this at the technical
control level. Human oversight (appeals via CITADEL) satisfies the AI-agent governance angle.

**EU AI Act overlap:** Art. 9 (risk management — Module 3 implements the runnable policy),
Art. 14 (human oversight — blocking + appeal flow), Art. 15 (cybersecurity — prompt injection
is explicitly an AI security threat under the Act's recitals).

### Module 4 — AI Threat Intelligence Feed (threat intelligence sharing)

Module 4 aggregates AI-attack indicators — prompt injection patterns, known malicious prompts,
AI-generated phishing templates, deepfake-hosting domains, model extraction signatures — and
publishes them to ThreatFlow in a STIX-compatible bundle with MITRE ATLAS tags.

**NIS3 relevance:** Cross-CSIRT AI-threat sharing is a central NIS3 projection. Module 4
already produces the IOC format (STIX + ATLAS) that NIS3 is expected to mandate. The gap is
federation: today ThreatFlow is the sole downstream; OpenCSIRT cross-border federation is
Phase 3. Once OpenCSIRT is live, Module 4 feeds directly into the projected NIS3 sharing
infrastructure.

**EU AI Act overlap:** Art. 9 (risk management — live threat intelligence informs AI risk
posture), Art. 55 (general-purpose AI model transparency — IOC sharing contributes to
ecosystem-wide visibility).

---

## 5. Recommended Actions Before NIS3 Ratification (2030-2032)

The following actions position VertGuard deployers for NIS3 compliance and position the
project for reference-tool status. Grouped by horizon:

### By v0.5.0 — 2027 Q3

- [ ] **Activate 7-year WORM retention** from day one. Every entry logged from v0.1 onward
  becomes NIS3 evidence. Default retention to 7+ years even before NIS3 mandates it.
- [ ] **Enable STIX export** from Module 4 for all AI-IOC events. Cross-CSIRT sharing will
  require this format; start producing it now so the pipeline is proven before federation
  is mandated.
- [ ] **Deploy Module 2** (AI phishing, v0.5). Multi-channel AI-phishing defence is a
  projected NIS3 explicit obligation. Deferring past 2027 leaves a gap through most of the
  NIS3 drafting period.
- [ ] **Run the first model card audit.** EU AI Act Art. 11 technical documentation is
  required now (Act in force). NIS3 will reference it. Model cards for all Phase 4.2 ML
  models must be complete and registered.

### By v1.0.0 — 2028 Q3

- [ ] **Commission a formal third-party security audit.** NIS3 is projected to require
  periodic independent audits for AI systems. Having a completed audit before the draft
  period (2028-2029) is the strongest evidence of readiness.
- [ ] **Implement signed ML model manifests (SBOM-equivalent).** Supply-chain provenance
  for ML artefacts is projected to be an explicit NIS3 obligation. Signed model cards
  planned for v1.1 must ship before NIS3 enters the draft phase.
- [ ] **Reach 10+ reference deployments across EU member states.** Regulators cite tools
  with demonstrable production history. 10 deployers by 2028 is the minimum threshold
  for citation in NIS3 preparatory studies.
- [ ] **Publish accuracy benchmarks publicly.** AI Act Art. 13 (transparency) and projected
  NIS3 effectiveness-assessment obligations both require published detection accuracy.
  False-positive rates by category must be publicly verifiable.

### By v3.0 — 2030 (NIS3 draft phase)

- [ ] **Complete post-quantum migration (PQ-default).** The ecosystem PQ roadmap targets
  v3.0 PQ-default. This must align with NIS3 ratification timing. Hybrid Ed25519 + ML-DSA
  available from v2.0 (2028); opt in early if risk model justifies.
- [ ] **Activate OpenCSIRT federation.** Cross-border CSIRT AI-threat sharing federation
  must be live before NIS3 transposition (2032). Phase 3 OpenCSIRT integration should be
  production-ready by 2030.
- [ ] **Engage ENISA on NIS3 preparatory studies.** Public comment windows open 6-12 weeks.
  Organisations running mature open-source tools with demonstrable EU deployment history
  get a seat at the table. Target: cited in at least one ENISA or Commission report before
  the legislative proposal is published.

---

## 6. EU AI Act Articles That Overlap with Projected NIS3 Obligations

NIS3 is expected to reference or cross-require EU AI Act obligations for AI systems used in
critical infrastructure. The following Act articles overlap directly with projected NIS3 scope:

| EU AI Act article | Subject | Projected NIS3 overlap |
|---|---|---|
| Art. 9 | Risk management system for high-risk AI | NIS3 AI risk management obligation; VertGuard Module 3 implements the technical control |
| Art. 10 | Data and data governance | NIS3 AI supply-chain provenance; VertGuard model + dataset registries |
| Art. 11 | Technical documentation | NIS3 audit and third-party assessment evidence; VertGuard model cards |
| Art. 12 | Record-keeping (logging) | NIS3 evidence retention; VertGuard CITADEL WORM satisfies both |
| Art. 13 | Transparency and provision of information | NIS3 transparency obligations; per-detection confidence + signer chain |
| Art. 14 | Human oversight | NIS3 AI-agent governance; CITADEL MARSHAL gate + appeal flow |
| Art. 15 | Accuracy, robustness, and cybersecurity | NIS3 explicit AI cybersecurity obligation; Module 3 is the primary control |
| Art. 53 | Obligations for GPAI model providers | NIS3 cross-CSIRT sharing; Module 4 IOC publication aligns with transparency obligations |
| Art. 55 | Obligations for GPAI models with systemic risk | NIS3 incident reporting for AI-related significant incidents |
| Annex III | High-risk AI system categories | NIS3 likely extends scope to AI systems in critical infrastructure |

**Note:** The EU AI Act has staggered applicability through 2027. GPAI provisions (Arts. 51-55)
apply from August 2025. High-risk system obligations (Art. 9-15) apply from August 2026.
NIS3 is expected to treat AI Act compliance as a baseline, not a ceiling — NIS3-specific
AI obligations will sit on top of, not in lieu of, Act obligations.

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| NIS3 timeline slips past 2032 | Reduced urgency; delayed regulatory clarity | VertGuard remains NIS2 Art. 21(e)-aligned regardless; evidence chain accumulates |
| Commission selects a different reference tool | Loss of reference status | Demonstrable EU deployment history + OSS audit transparency is the strongest counter |
| EU AI Act amendments absorb AI-defence scope | NIS3 defers to Act on AI-attack obligations | VertGuard is AI-Act-aligned already; either instrument validates the controls |
| PQC mandate accelerated before 2030 | Asymmetric signing gaps become compliance issues | Hybrid Ed25519 + ML-DSA available v2.0 (2028); opt-in supported early |

---

## Related

- [nis2-ai-act-mapping.md](nis2-ai-act-mapping.md) — current NIS2 + EU AI Act control mapping
- [security-model.md](security-model.md) — threat boundaries and cryptographic controls
- [citadel-integration.md](citadel-integration.md) — WORM evidence chain
- [mitre-atlas-mapping.md](mitre-atlas-mapping.md) — ATLAS taxonomy alignment
- [../../docs/post-quantum-roadmap.md](../../docs/post-quantum-roadmap.md) — PQ migration timeline
- [../../adrs/ADR-010-vertguard-platform-strategy.md](../../adrs/ADR-010-vertguard-platform-strategy.md)
- [../../adrs/ADR-011-post-quantum-agility.md](../../adrs/ADR-011-post-quantum-agility.md)
- [NIS2 Directive text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555)
- [EU AI Act consolidated text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)
- [ENISA NIS2 implementation guidance](https://www.enisa.europa.eu/topics/cybersecurity-policy/nis-directive-new)
