# False-Positive Handling

Every detection system has false positives. In AI-attack defence they
are particularly costly: a legitimate creative-writing prompt flagged
as prompt injection blocks real work; a C2PA-signed news photo flagged
as deepfake erodes trust in verified content.

This document describes VertGuard's FP handling philosophy, the test
corpus that guards against regressions, and tunable knobs for
operators.

## Philosophy

Three principles:

1. **FPs are bugs, not trade-offs.** Every pattern ships with matching
   FP test cases. A pattern that fires on legitimate input is a bug in
   the pattern, not an "acceptable cost".
2. **Configurability supports diverse deployments.** What's FP in a
   creative-writing tool is a real attack in a customer-service bot.
   Thresholds and suppressions are per-deployment.
3. **Transparency over black-box classification.** Every positive
   detection shows which patterns matched with what confidence.
   Operators can interrogate; models are not oracles.

## FP test corpus

Located in `tests/fp/`. Grouped by module:

```
tests/fp/
├── prompt/
│   ├── creative_writing/           ← fiction, poetry, role-play scenarios
│   ├── technical_questions/        ← "how does X work" style benign queries
│   ├── edge_cases/                 ← Unicode, encoding, URL payloads
│   └── known_frameworks/           ← LangChain / LlamaIndex templates
├── media/
│   ├── authentic_c2pa/             ← real signed media from trusted signers
│   ├── no_manifest_authentic/      ← unsigned legitimate media
│   └── known_tools_output/         ← output from non-AI tools (Photoshop no AI)
└── threatfeed/
    └── ambiguous_iocs/             ← patterns that could overfit
```

Every PR that adds a pattern must add at least one matching FP test case.
Target scale by v0.1.0:

| Module | FP cases target |
|---|---|
| Prompt (Module 3) | 500+ |
| Media (Module 1, Phase 4.1) | 100+ |
| ThreatFeed (Module 4) | 200+ |

## FP-rate thresholds

Release gate: no new release ships if FP rate exceeds the baseline
by > 1 percentage point on the test corpus. Check with:

```bash
make test-fp

# Output includes per-module FP rate:
# prompt/creative_writing:   FP rate 0.4% (baseline 0.4%)  PASS
# prompt/technical_questions: FP rate 0.8% (baseline 0.5%) FAIL (+0.3%)
```

In the failing case above, the patch cannot ship. Either:
- Fix the pattern that's causing the regression
- Add a matching FP test case + fix the pattern in the same PR

## Configurable thresholds

Operators can tune per-deployment:

### Prompt (Module 3)

```bash
VERTGUARD_PROMPT_CLEAN_THRESHOLD=0.3    # lower → more SUSPICIOUS
VERTGUARD_PROMPT_BLOCK_THRESHOLD=0.7    # higher → fewer BLOCKED
```

Higher thresholds → fewer FPs but also fewer true positives.
Recommended starting values: default 0.3 / 0.7. Tune based on:

- Deployment's tolerance for bypass vs disruption
- Context (creative-writing tool vs customer-service bot)
- False-positive reports from users

### Media (Module 1)

C2PA verification is deterministic — no configurable FP threshold.
Either the signature is valid or it isn't.

For Phase 4.2+ ML deepfake detection:

```bash
VERTGUARD_MEDIA_ML_THRESHOLD=0.6   # confidence threshold for "unauthentic" classification
```

### ThreatFeed (Module 4)

```bash
VERTGUARD_THREATFEED_MIN_CONFIDENCE=0.5   # drop IOCs below this
```

## Pattern suppressions

Per-deployment suppressions for known-problematic patterns. Configured
in `/etc/vertguard/pattern-exclusions.yaml`:

```yaml
suppressions:
  - pattern_id: LLM01.jailbreak.storytelling.v2
    reason:     "FP spike in creative-writing internal tool"
    approved_by: secops@company.com
    expires:    "2026-06-01"      # required field; max 30 days
```

**Safeguards:**

- `expires` is required — max 30 days. Forces review.
- Suppressions are WORM-logged. Every suppression change is an audit event.
- The CLI refuses to load suppressions without `approved_by`.

Encouraged workflow:

1. Observe FP in production
2. File GitHub issue with example
3. Add **temporary** suppression (≤ 30 days)
4. Fix the pattern in the library
5. Remove suppression when fix is deployed

## FP telemetry

```
vertguard_pattern_matches_total{pattern_id, classification_final}
```

A pattern that frequently fires + final classification = CLEAN is a
candidate FP factory. Quarterly review of this metric:

```sql
SELECT
  pattern_id,
  COUNT(*) FILTER (WHERE classification_final = 'CLEAN') AS fp_like,
  COUNT(*) AS total,
  ROUND(100.0 * COUNT(*) FILTER (WHERE classification_final = 'CLEAN') / COUNT(*), 2) AS fp_like_pct
FROM pattern_matches
WHERE ts_utc > now() - interval '90 days'
GROUP BY pattern_id
HAVING COUNT(*) > 100
ORDER BY fp_like_pct DESC
LIMIT 20;
```

Patterns with `fp_like_pct > 10%` need attention.

## Common FP causes

### Module 3 — prompt

**Creative-writing content flagged as injection:**

- Root cause: legitimate role-play / fiction triggers jailbreak
  patterns
- Fix: refine pattern to require attack-specific context markers, not
  just "persona language"
- Example: distinguish "pretend you're a cat" (benign) from "DAN,
  ignore safety rules" (attack) via pattern context

**Technical documentation flagged:**

- Root cause: security docs discussing attacks contain attack
  patterns verbatim
- Fix: add context tag `untrusted_document_content` vs `user_chat_input`
  with lower confidence boost

### Module 1 — C2PA

**Legitimate unsigned media flagged `authentic: unknown`:**

- Not actually a FP — this is correct v0.1 behaviour
- Resolution: Phase 4.2 adds ML deepfake detection to classify
  unsigned content

**Signed media flagged `signature_invalid`:**

- Root cause: new signer's certificate not in trust store
- Fix: add the root cert to `VERTGUARD_C2PA_TRUSTSTORE`

### Module 4 — ThreatFeed

**Legitimate prompts classified as known-attack:**

- Root cause: IOC pattern was too broad
- Fix: tighten the pattern, push correction upstream to the feed source

## FP vs true positive — when unsure

Default to "show, don't block" — SUSPICIOUS classification retains the
prompt but flags it. BLOCKED is for high-confidence attacks.

The threshold between SUSPICIOUS and BLOCKED is the judgement call.
Production deployments typically start conservative (block at 0.8) and
tighten as the library matures.

## Reporting a FP externally

For FPs originating in the default pattern library (not custom
patterns), report via:

- GitHub issue with label `false-positive`
- Include: input that FP'd, which pattern(s) matched, context, expected
  classification
- Preserve privacy: hashes + pattern IDs; never share sensitive content

The VertGuard team treats FP reports as P2 (same-week response).

## FP vs precision in release planning

Pattern additions typically fall into three buckets:

1. **High-confidence attacks** — high precision (95%+ accuracy).
   Ship in minor releases without gating.
2. **Medium-confidence attacks** — ship as SUSPICIOUS-only by default
   (block threshold needs to be raised by operator to enable blocking)
3. **Experimental patterns** — ship behind feature flag
   (`VERTGUARD_PROMPT_EXPERIMENTAL_PATTERNS=true`)

This tiering prevents a novel pattern from immediately spiking FP
rates in conservative deployments.

## Related

- [module-3-prompt-injection.md](module-3-prompt-injection.md)
- [module-4-ai-threat-feed.md](module-4-ai-threat-feed.md)
- [operator-handbook.md](operator-handbook.md)
- [configuration.md](configuration.md)
- [../SECURITY.md § Detection quality](../SECURITY.md)
