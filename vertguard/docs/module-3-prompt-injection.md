# Module 3 — Prompt Injection Defence

**Status:** Phase 4.1 — Active development.

This module is VertGuard's first-line defence against attacks on
LLM-powered applications: prompt injection, jailbreaks, indirect
injection, instruction overrides, and the broader OWASP LLM Top 10
input-side categories.

For the cross-cutting OWASP coverage matrix, see
[owasp-llm-top10-coverage.md](owasp-llm-top10-coverage.md). For the
architecture, see [architecture.md](architecture.md).

## Scope

Module 3 covers input-side attacks **before** they reach the target
LLM. It does **not**:

- Train or fine-tune LLMs.
- Monitor LLM outputs (that's a separate concern — LLM firewall, see
  "LLM firewall integration" below).
- Detect AI-generated content (that's Module 1 / Module 5 territory).
- Classify generic "unsafe" prompts by content (we look at structure
  and pattern, not semantics).

### What we detect

- **LLM01 Prompt Injection** — direct attempts to override instructions
- **Jailbreaks** — known bypass patterns (DAN, role-plays, persona
  takeovers, hypothetical framings)
- **Indirect injection** — payloads embedded in documents, URLs, or
  other "content" that the LLM will subsequently process
- **Encoded / obfuscated attacks** — Unicode tricks, zero-width spaces,
  Base64, homoglyph substitution
- **Instruction-override attempts** — "ignore previous", "forget all
  rules", "your new persona"
- **Context-boundary attacks** — fake conversation markers, fake system
  messages, context-length manipulation

### What we don't detect

- **Semantic policy violations** — whether a request is "unethical" is a
  policy question. We flag structural attacks, not content policy.
- **Adversarial outputs** — post-generation filtering lives elsewhere.
- **Model extraction** — behavioural attacks that probe the model over
  many queries. Rate-limiting is the defence; not us.

## Architecture

```
HTTP POST /api/v1/prompt/scan
      │
      ▼
┌─────────────────────────────────────┐
│ Go orchestrator (internal/prompt/)  │
│  • SoD/RBAC check                   │
│  • Input normalisation (UTF-8, etc) │
│  • Rate limiting                    │
└──────────────┬──────────────────────┘
               │ FFI or subprocess
               ▼
┌─────────────────────────────────────┐
│ Rust pattern engine                 │
│  (rust/prompt-patterns/)            │
│  • Load pattern library             │
│  • Multi-pattern scan (regex + AC)  │
│  • Per-match confidence scoring     │
│  • Byte-range tagging               │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Go scorer (internal/prompt/scorer.go)│
│  • Aggregate matches                │
│  • Threshold-based classification   │
│    CLEAN | SUSPICIOUS | BLOCKED     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ CITADEL WORM emit (if BLOCKED)      │
│ Response: JSON with matches[]       │
└─────────────────────────────────────┘
```

## Pattern library organisation

Patterns live in the Rust crate `rust/prompt-patterns/src/`:

```
rust/prompt-patterns/
├── Cargo.toml
└── src/
    ├── lib.rs              — public API: Engine::scan(input)
    ├── patterns.rs         — pattern-definition structs + loader
    ├── owasp_llm.rs        — OWASP LLM Top 10 pattern catalogue
    ├── indirect.rs         — indirect injection patterns
    ├── jailbreak.rs        — jailbreak patterns (DAN, etc.)
    ├── encoding.rs         — Unicode / Base64 / homoglyph detection
    └── error.rs
```

### Pattern definition

```rust
pub struct Pattern {
    pub id:          &'static str,    // e.g. "LLM01.instruction_override.v1"
    pub category:    OwaspCategory,   // LLM01 .. LLM10
    pub description: &'static str,
    pub matcher:     Matcher,         // Regex, AhoCorasick, or CustomFn
    pub base_score:  f32,             // 0.0..1.0 baseline confidence
    pub version:     u16,             // increments on refinement
}

pub enum Matcher {
    Regex(regex::Regex),
    AhoCorasick(aho_corasick::AhoCorasick),
    Custom(fn(&str) -> Vec<ByteRange>),
}
```

### Example pattern

```rust
Pattern {
    id:          "LLM01.instruction_override.v1",
    category:    OwaspCategory::LLM01,
    description: "Attempts to override prior instructions",
    matcher:     Matcher::Regex(Regex::new(
        r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?|orders?)"
    ).unwrap()),
    base_score:  0.95,
    version:     1,
}
```

## Classification thresholds

Module 3 returns one of three classifications:

| Classification | Condition | Action |
|---|---|---|
| **CLEAN** | No matches; aggregated confidence < `clean_threshold` (default 0.3) | Pass the prompt to the LLM unchanged |
| **SUSPICIOUS** | Matches exist; aggregated confidence in [0.3, 0.7) | Pass with warning (optionally sanitise) |
| **BLOCKED** | Aggregated confidence ≥ `block_threshold` (default 0.7) | Refuse the prompt; emit WORM entry |

Aggregation rule: `max(match.confidence for all matches) * severity_boost(category)`.

Thresholds configurable via `VERTGUARD_PROMPT_THRESHOLDS_*` env vars
(see [configuration.md § Prompt thresholds](configuration.md)).

## Confidence scoring

Each pattern carries a `base_score`. Aggregation applies:

1. **Category boost** — LLM01 (Prompt Injection, the highest-risk
   category) gets +0.1; LLM06 (Sensitive Information Disclosure) gets
   +0.05; others unchanged.
2. **Multiple-match boost** — two or more patterns matching the same
   input: +0.05 per additional match (capped at +0.15).
3. **Context degradation** — when `context` field in the scan request
   indicates a trusted source (e.g. `context: "internal_dev_tool"`),
   scores reduce by 0.2 (configurable).

Final score clamped to [0, 1].

## The `context` field

Callers can pass `context` to inform scoring:

| context value | Score adjustment |
|---|---|
| `user_chat_input` | none (default assumption) |
| `authenticated_operator` | −0.1 |
| `internal_dev_tool` | −0.2 |
| `untrusted_third_party` | +0.1 |
| `untrusted_document_content` | +0.2 (indirect-injection boost) |

This is a hint, not a bypass — a BLOCKED match stays BLOCKED
regardless of context.

## LLM firewall integration

Module 3 **scans input**. Complementary output-side filtering (LLM
firewall) integrates with:

- **NeMo Guardrails (NVIDIA)** — `VERTGUARD_NEMO_ENDPOINT` connects
  VertGuard as a pre-filter ahead of NeMo's runtime rules.
- **Llama Guard (Meta)** — `VERTGUARD_LLAMAGUARD_ENDPOINT` for output
  policy classification.

These are **optional** — VertGuard Module 3 operates standalone for
input-side defence. Integration recipes: [owasp-llm-top10-coverage.md](owasp-llm-top10-coverage.md).

## Pattern refresh

Pattern-library updates ship via:

1. **Code release** — `rust/prompt-patterns` crate bump → new VertGuard
   release.
2. **Runtime registry** — `internal/prompt/patterns_client.go` can
   load patterns from `pattern-registry.yaml` without a redeploy, for
   urgent pattern additions between releases.

Rhythm: the crate targets **quarterly** pattern refreshes. Pattern
additions are typically **minor** version bumps; the matching false-positive
test corpus is expanded alongside.

## Custom patterns

Operators can add deployment-specific patterns without modifying the
Rust crate:

```yaml
# custom-patterns.yaml
- id:           custom.company_secret_exfil.v1
  category:     CUSTOM
  description:  Attempts to extract our internal secrets
  matcher_type: regex
  matcher:      "(?i)(show|reveal|leak|extract).+\\b(api[ _-]?key|secret|token|password)\\b"
  base_score:   0.85
```

Loaded via `VERTGUARD_CUSTOM_PATTERNS_PATH=/etc/vertguard/custom-patterns.yaml`.

**Custom patterns don't ship in the default library.** Operators own
their correctness and update cadence.

## Metrics

| Metric | Description |
|---|---|
| `vertguard_prompt_scans_total{classification}` | Total prompts scanned, by outcome |
| `vertguard_prompt_pattern_matches_total{pattern_id, category}` | Per-pattern match counter |
| `vertguard_prompt_scan_latency_seconds{quantile}` | Latency histogram |
| `vertguard_prompt_blocked_by_category_total{category}` | BLOCKED outcomes by OWASP LLM category |

Suggested alert: sustained increase in `vertguard_prompt_blocked_total`
rate — may indicate targeted attack campaign.

## False-positive handling

Every pattern has matching false-positive test cases in `tests/fp/`.
Adding a pattern requires adding at least one legitimate-looking input
that must NOT match.

Tunable per-deployment:

- Adjust `block_threshold` upward to reduce FPs at cost of more
  slip-through.
- Use `custom-exclusions.yaml` to whitelist specific patterns for known
  internal use cases.

Full guide: [false-positive-handling.md](false-positive-handling.md).

## Performance

Target (mid-range hardware, single-threaded):

- **Input < 1 KB:** < 5 ms p95
- **Input < 10 KB:** < 50 ms p95
- **Input < 100 KB (indirect injection from document):** < 500 ms p95

Input size hard-limited to 1 MB by default
(`VERTGUARD_PROMPT_MAX_INPUT_SIZE`). Above limit: 413 Payload Too Large.

## Integration with ecosystem

- **CITADEL:** every BLOCKED classification emits `vertguard.detection.prompt_injection`
  to WORM with the Kerkese context.
- **IRFlow:** BLOCKED events with `severity: high` trigger IRFlow
  incident creation via webhook.
- **ThreatFlow:** novel patterns observed at runtime (input that
  matches no known pattern but looks structurally suspicious —
  behavioural heuristic, v0.3+) feed back as new AI-IOCs.
- **SecureLab (Phase 3):** Module 3 patterns get tested against
  SecureLab's red-team prompt corpus for evasion.

## Open issues (Phase 4.1 scope)

- [ ] Initial OWASP LLM Top 10 pattern coverage (target: 80% by v0.1.0)
- [ ] Indirect injection patterns (document-embedded payloads)
- [ ] Jailbreak pattern library (DAN, persona takeovers, etc.)
- [ ] Unicode obfuscation detection
- [ ] Confidence scoring calibration across categories
- [ ] False-positive test corpus (target: 500+ benign cases by v0.1.0)
- [ ] NeMo Guardrails integration adapter
- [ ] Pattern-registry hot-reload (without restart)

## Related

- [owasp-llm-top10-coverage.md](owasp-llm-top10-coverage.md) — coverage matrix
- [mitre-atlas-mapping.md](mitre-atlas-mapping.md) — ATLAS technique links
- [false-positive-handling.md](false-positive-handling.md)
- [api.md § POST /api/v1/prompt/scan](api.md) — HTTP wire format
- [architecture.md](architecture.md)
