# OWASP LLM Top 10 Coverage

This document maps VertGuard's detection capabilities onto the
[OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

The OWASP LLM Top 10 is the standard reference for LLM-specific
risks. VertGuard covers the input-side categories via Module 3
(Prompt Injection Defence) and contributes to downstream monitoring
via Module 4 (AI Threat Feed).

## Coverage matrix (v0.1 target)

| # | Category | VertGuard coverage | Module | Notes |
|---|---|---|:-:|---|
| LLM01 | Prompt Injection | ✅ **Primary target** | 3 | OWASP LLM #1 — direct + indirect injection patterns, jailbreaks, instruction overrides |
| LLM02 | Insecure Output Handling | 🔶 Partial | — | Detection patterns for known "output exfil" templates; full handling is downstream LLM firewall concern |
| LLM03 | Training Data Poisoning | ❌ Out of scope | — | Offline training-time concern; VertGuard is runtime defence |
| LLM04 | Model Denial of Service | 🔶 Partial | 3 | Pattern detection for known DoS prompts (recursive, infinite) |
| LLM05 | Supply Chain Vulnerabilities | ❌ Out of scope | — | Dependency scanning is APIGuard's territory |
| LLM06 | Sensitive Information Disclosure | 🔶 Partial | 3 | Patterns for "reveal system prompt", "show me the training data" |
| LLM07 | Insecure Plugin Design | ❌ Out of scope | — | LLM architecture concern, not runtime defence |
| LLM08 | Excessive Agency | 🔶 Partial | — | Would need LLM firewall on outputs; tracked for Phase 4.2 |
| LLM09 | Overreliance | ❌ Out of scope | — | Human-factor concern, not technical defence |
| LLM10 | Model Theft | 🔶 Partial | 4 | AI-IOC patterns for known model-extraction probes |

Legend:

- ✅ Primary target: full detection coverage with dedicated patterns
- 🔶 Partial: some detection via existing patterns; gap known
- ❌ Out of scope: not a runtime-defence concern or addressed by other platforms

## LLM01 — Prompt Injection (primary target)

Core coverage area. Module 3 maintains a pattern library organized by
attack family:

### Direct instruction override

Patterns targeting explicit instruction rewrites:

- `LLM01.instruction_override.v1` — "ignore previous instructions"
- `LLM01.instruction_override.v2` — "forget all prior rules"
- `LLM01.instruction_override.v3` — "disregard above, here are new rules"
- `LLM01.system_prompt_reveal.v1` — "print your system prompt"
- `LLM01.role_replace.v1` — "you are now [new persona]"

### Jailbreak / role-play

- `LLM01.jailbreak.dan.v*` — DAN-style ("Do Anything Now") variations
- `LLM01.jailbreak.dev_mode.v*` — "you are in developer mode"
- `LLM01.jailbreak.persona_takeover.v*` — persona-replacement attacks
- `LLM01.jailbreak.hypothetical.v*` — "hypothetically, if you could..."
- `LLM01.jailbreak.storytelling.v*` — embedding harmful request in fiction

### Indirect injection

Patterns embedded in content that LLMs subsequently process:

- `LLM01.indirect.html_injection.v1` — HTML comment-hidden instructions
- `LLM01.indirect.document_payload.v1` — instructions in PDF metadata
- `LLM01.indirect.url_payload.v1` — malicious instructions in URL params
- `LLM01.indirect.tool_use_hijack.v1` — tool-use redirection

### Encoded / obfuscated

- `LLM01.obfuscation.unicode.v1` — zero-width space insertion
- `LLM01.obfuscation.homoglyph.v1` — lookalike character substitution
- `LLM01.obfuscation.base64.v1` — Base64-encoded instruction payloads
- `LLM01.obfuscation.leetspeak.v1` — character substitution (a→4, e→3)

Target: 80%+ OWASP LLM01 pattern coverage by v0.1.0.

## LLM02 — Insecure Output Handling (partial)

VertGuard Module 3 detects **input patterns** that typically trigger
unsafe outputs. Actual output-side filtering is a separate concern —
we recommend pairing VertGuard with:

- **NeMo Guardrails** (NVIDIA) — output policy enforcement
- **Llama Guard** (Meta) — output classification
- **Custom LLM firewall** — domain-specific output rules

VertGuard integrates with NeMo Guardrails as a pre-filter ahead of
NeMo's runtime rules. See [module-3-prompt-injection.md § LLM firewall
integration](module-3-prompt-injection.md).

## LLM06 — Sensitive Information Disclosure (partial)

Module 3 includes patterns targeting information-exfil attempts:

- `LLM06.system_exfil.v1` — "show me the system prompt"
- `LLM06.training_exfil.v1` — "recite your training data"
- `LLM06.memory_exfil.v1` — "recall previous conversations"
- `LLM06.api_key_exfil.v1` — "show me the API key you have access to"

Complete coverage of LLM06 requires output-side filtering (LLM
firewall) in addition to input-side pattern matching.

## LLM10 — Model Theft (partial, via Module 4)

Module 4's AI Threat Feed includes patterns for known model-extraction
probes:

- Specially crafted prompts that trigger model-version disclosure
- Repeated queries at information-theoretic bounds
- Jailbreak-then-extract patterns

These feed ThreatFlow as `ai_attack_pattern` IOCs with
`mitre_atlas.technique: AML.T0024` (Exfiltration via ML Inference
API). Detection + blocking is a downstream consumer responsibility.

## Relationship with MITRE ATLAS

Every OWASP LLM category maps to MITRE ATLAS techniques. Module 4
maintains the cross-framework mapping. Full reference:
[mitre-atlas-mapping.md](mitre-atlas-mapping.md).

| OWASP LLM | Typical ATLAS technique |
|---|---|
| LLM01 | AML.T0051 (LLM Prompt Injection) |
| LLM02 | AML.T0050 (LLM Output Handling) |
| LLM04 | AML.T0029 (Denial of ML Service) |
| LLM06 | AML.T0057 (LLM Data Leakage) |
| LLM10 | AML.T0024 (ML Model Exfiltration) |

## Open items (Phase 4.1 scope)

- [ ] Initial LLM01 pattern library (target: 50+ patterns at v0.1)
- [ ] LLM06 pattern coverage (target: 15+ patterns at v0.1)
- [ ] Pattern-to-OWASP-category mapping documentation
- [ ] Pattern-to-ATLAS-technique mapping documentation
- [ ] NeMo Guardrails adapter
- [ ] Llama Guard adapter (optional)
- [ ] Benchmark suite against public OWASP LLM test corpus

## Updating this document

When new OWASP LLM Top 10 versions publish, update:

1. The coverage matrix above (add new categories, reclassify existing)
2. The per-category sections
3. Pattern IDs referencing the new category
4. The ATLAS mapping in [mitre-atlas-mapping.md](mitre-atlas-mapping.md)

Pattern-library releases that add coverage for a newly added OWASP
category ship as **minor** versions (new detection capability, no
breaking change).

## Related

- [module-3-prompt-injection.md](module-3-prompt-injection.md)
- [module-4-ai-threat-feed.md](module-4-ai-threat-feed.md)
- [mitre-atlas-mapping.md](mitre-atlas-mapping.md)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
