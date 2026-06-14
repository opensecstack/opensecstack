# RFC-0004: VertGuard — AI-Attack Defence Platform

**Status:** Draft — open for community comment
**Author:** core-maintainers
**Date posted:** 2026-04-20
**Comment deadline:** 2026-05-20 (30 days)
**Related:** [ADR-010 VertGuard Platform Strategy](../adrs/ADR-010-vertguard-platform-strategy.md), [ROADMAP.md § Phase 4](../ROADMAP.md#phase-4--ai-attack-defence-2026-q3--2028-q4)

---

## Summary

Add VertGuard as the 10th platform in the OpenSecStack ecosystem.
VertGuard covers AI-generated threats that none of the existing 9
platforms address: deepfakes (image/video/audio), AI-generated
phishing, prompt injection against LLM applications, AI threat
intelligence, and synthetic identity detection.

This RFC invites community feedback on the platform scope, phased
rollout, naming, and integration choices **before** work begins in
Phase 4.1 (2026 Q4).

## Motivation

### Why now

By 2026, AI-generative threats are mainstream attack vectors:

- AI-generated phishing has grown ~400% in 2024-2026.
- Voice-clone CEO fraud has cost organisations €25M+ in confirmed
  losses.
- Prompt injection is OWASP LLM Top 10 #1.
- Deepfake-enabled disinformation has influenced elections across
  multiple democracies.

None of these are addressed by classical cybersecurity platforms.
Specialised detection is required — ML models, C2PA provenance, LLM
input sanitisation — outside the normal operational scope of API
scanners or incident response tools.

### Why us (OpenSecStack)

- **Market gap:** no production-grade OSS alternative exists. Commercial
  options (Reality Defender, Lakera, Protect AI) are SaaS, non-EU-sovereign,
  and cost €30k-€300k/year.
- **Regulatory trajectory:** NIS3 (expected 2030-2032) likely mandates
  AI-attack defence for essential entities. We have a 4-6-year window
  to become the reference tool.
- **Architectural fit:** our ecosystem already has the governance
  (CITADEL), threat intel (ThreatFlow), and incident response
  (IRFlow) infrastructure that VertGuard integrates naturally with.
- **NIS3 coverage gap:** without VertGuard, our claim of
  "NIS3-ready ecosystem" is incomplete.

## Proposal

### Scope

Five modules, deployed in three phases:

| Module | Purpose | Tech | Phase |
|---|---|---|---|
| 1. Media Authenticity | C2PA provenance + deepfake detection | Rust + Python ML | 4.2 (2027 H2) |
| 2. AI Phishing Detection | LLM-generated email/chat classification | Python ML | 4.2 (2027 H2) |
| 3. Prompt Injection Defence | OWASP LLM Top 10 scanner + LLM firewall | Rust + Go | **4.1 (2026 H2)** |
| 4. AI Threat Intelligence Feed | AI-specific IOCs, MITRE ATLAS mapping | Go | **4.1 (2026 H2)** |
| 5. Synthetic Identity Detection | GAN profiles + real-time video call analysis | Python ML | 4.3 (2028 H2) |

### Architecture

```
┌─────────────────────────────────────────────┐
│  Go orchestrator (same pattern as all 9     │
│  platforms) — HTTP API, CITADEL integration │
└──────────┬───────────────────────┬──────────┘
           │                       │
   ┌───────▼──────┐         ┌──────▼──────────┐
   │ Rust layer   │         │ Python ML layer │
   │ C2PA, prompt │         │ (Phase 4.2+)    │
   │ patterns,    │         │ gRPC service    │
   │ audio FFT    │         │ HuggingFace zoo │
   └──────────────┘         └─────────────────┘
```

- **Go**: orchestration, HTTP API, CITADEL + ThreatFlow integration
- **Rust**: C2PA bindings (via `c2pa-rs`), prompt injection pattern
  engine, audio fingerprinting
- **Python ML**: gRPC side-car for inference; HuggingFace model zoo
  adapters; runs in a separate process for fault isolation
- **Model registry** (`models.yaml`): SHA-256-checksummed public models
  downloaded on first run, never committed to git
- **Dataset registry** (`datasets.yaml`): same pattern for test
  datasets; addresses licensing, privacy, and repo-size concerns

### Name

- Working name: **VertGuard**
- Albanian-first alternative: **Vërtet** (means "truly, authentically")
- Final name to be decided during this RFC comment period.

### Licence

**AGPL-3.0** — consistent with other governance-adjacent platforms
(CITADEL, IRFlow, NIS2 Compass, OpenCSIRT). VertGuard produces
evidence that enters the audit chain; copyleft prevents closed-source
forks of a trust component.

### Ports

- API: **8091** (next after NIS2 Compass's 8090)
- Dashboard: **3009**
- gRPC ML side-car: **50051** (internal-only, Phase 4.2+)

## Questions for the community

We specifically invite comment on:

### 1. Naming

- Is **VertGuard** clear enough internationally?
- Does **Vërtet** risk confusing non-Albanian audiences?
- Should we brand differently in EU vs global contexts?

### 2. Scope — what to add, what to cut

- Are the 5 modules the right grouping, or should we split (e.g.
  Module 1 separate from Module 2)?
- Is there an obvious AI-threat category we missed? Propose additions.
- Is Module 5 (synthetic identity, real-time video call) over-ambitious
  for v1.0? Should we defer it to v2.0?

### 3. Phase ordering

- Phase 4.1 ships Modules 3 + 4 (no ML). Is this the right pair for
  first-mover value?
- Would Module 1's C2PA-only portion (no ML) fit better in Phase 4.1?

### 4. LLM firewall integration

- Ship NeMo Guardrails (NVIDIA) by default? Llama Guard (Meta)? Both?
  Make it configurable?
- Should we build our own minimal guardrail layer instead of
  depending on third-party projects?

### 5. ML deployment topology

- Python ML service as side-car (per VertGuard pod)?
- Or shared cluster-wide GPU pool with a dedicated inference service?
- Side-car: simpler ops, duplicated GPU memory.
- Shared: efficient GPU use, more complex to deploy and secure.

### 6. Commercial / support model

- Does the ecosystem need a commercial-support offering for VertGuard
  specifically, given the ML operational complexity?
- If yes: separate entity or through the OpenSecStack Foundation (once
  established)?

### 7. Privacy concerns

- Media scanning requires access to content. How do we handle
  privacy-sensitive deployments?
- Is on-device inference (edge deployment) necessary for v1.0, or can
  that be a post-v1.0 feature?

### 8. Adversarial robustness

- Attackers will adapt detectors. What's our research engagement
  strategy?
- University partnerships? Academic grants? Bug-bounty program?

## Alternatives considered

See [ADR-010](../adrs/ADR-010-vertguard-platform-strategy.md) for the
full analysis. In summary:

- **Don't build it** — leaves a coverage gap that competitors fill.
- **Distribute across existing platforms** — fragments the detection
  story; no coherent "where do I go for AI defence?" answer.
- **Delay entirely until 2028** — misses first-mover advantage in
  prompt-injection market.
- **Build all 5 modules immediately** — requires ML hires we don't
  have; disrupts Phase 1 completion.

**Chosen:** staggered platform that launches in Phase 4.1 with Go/Rust
modules (no ML dependency), adds ML in Phase 4.2, and completes at
v1.0 in Phase 4.3.

## Risks

| Risk | Mitigation |
|---|---|
| ML model refresh cycle outpaces our release cycle | Model registry with pluggable adapters; no hard-coded models |
| False positives erode trust | Configurable confidence thresholds; extensive `tests/fp/` suite |
| Adversarial evasion | Research partnerships; quarterly model updates |
| Scope creep — another platform to maintain | Monorepo structure; shared CI/CD with existing 9 platforms |
| ML talent acquisition for Phase 4.2 | Phase 4.1 generates revenue to fund hires; EU Horizon Europe grant path |
| Privacy backlash | On-device inference roadmap; clear data-handling docs; `docs/privacy-ml-inference.md` |

## Open items to resolve during comment period

- [ ] Finalise name (VertGuard vs Vërtet vs alternative).
- [ ] Confirm AGPL-3.0 licence (no alternative proposed yet).
- [ ] Confirm port allocation 8091 (no conflict expected).
- [ ] Decide ML topology (side-car vs shared) — technical spike during
      Phase 4.1 planning.
- [ ] Identify platform lead (internal promotion or external hire).

## Next steps

1. **Comment period:** 30 days from publication (closes 2026-05-20).
2. **Comment integration:** substantive feedback folded into ADR-010
   revisions.
3. **Final decision:** core-maintainers vote at 2026 Q2 community meeting.
4. **Kickoff:** if approved, `opensecstack/vertguard/` directory
   created 2026 Q3, first commit targets Phase 4.1 v0.1.0-rc1 by
   2026 Q4.

## How to comment

- **GitHub Discussion:** comment on the "RFC-0004 VertGuard" thread
  (linked in the announcement).
- **GitHub Issues:** file an issue with label `rfc-0004` for
  substantive technical concerns.
- **Email:** `rfcs@opensecstack.org` for private or confidential
  feedback.

The goal of this RFC is to find flaws **before** implementation,
when changes are cheap. Blunt feedback is welcome.

## References

- [ADR-010 VertGuard Platform Strategy](../adrs/ADR-010-vertguard-platform-strategy.md)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/) — Adversarial Threat Landscape for AI Systems
- [C2PA specification](https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html)
- NIS3 preparatory studies (pending publication, Q3 2027)
