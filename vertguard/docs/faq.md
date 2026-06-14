# VertGuard FAQ

Conceptual questions about what VertGuard is, what it is **not**, and
how it fits into the opensecstack ecosystem. For symptom-driven
debugging, jump to [troubleshooting.md](troubleshooting.md). For deep
dives into a specific subsystem, see the per-module docs in this
directory.

---

## What does VertGuard do?

VertGuard guards the *human-AI* and *human-document* trust boundary. It
hosts six modules — media authenticity, AI phishing detection, prompt
injection scanning, AI threat-feed ingestion, synthetic-identity
detection, and identity verification — that share an HTTP API, a
PostgreSQL persistence layer, JWT-gated access control, and CITADEL
WORM-backed governance.

Concretely it answers questions like:

- *"Was this image AI-generated, edited, or genuinely captured?"*
  (Module 1, C2PA + TripleHash)
- *"Is this email/URL/HTML attempting phishing?"* (Module 2)
- *"Is this LLM prompt trying to jailbreak the system?"* (Module 3)
- *"What known AI-attack patterns match this artefact?"* (Module 4,
  MITRE ATLAS)
- *"Does this identity claim look synthetic?"* (Module 5)
- *"Is this document genuine, and has it been replayed?"* (Module 6)

---

## What does VertGuard *not* do?

- **It is not an EDR / network IDS.** Endpoint and traffic-level
  threat detection are out of scope; pair VertGuard with APIGuard and
  ThreatFlow for full ecosystem coverage.
- **It does not store raw user content.** Scans persist hashes,
  classifications, and structured indicators only — never the original
  prompt, image bytes, or document text. See
  [data-model.md](data-model.md) for the privacy-by-schema design.
- **It does not own threat intel.** Module 4 ingests and correlates
  IOCs but the canonical threat repository is ThreatFlow.
- **It does not authenticate end users.** API keys + JWT auth gate
  *operator* access. End-user auth is the calling application's
  responsibility.

---

## How does VertGuard relate to the rest of opensecstack?

| Service | Relationship |
|---------|--------------|
| **CITADEL** | Every state-changing call is MARSHAL-evaluated; outcomes WORM-logged. |
| **ThreatFlow** | Module 4 sources IOCs from ThreatFlow; webhook subscribers receive `*.scanned` events. |
| **APIGuard** | APIGuard inspects API traffic; when it sees an LLM endpoint, it can call VertGuard's prompt scan. |
| **NIS2 Compass** | The control mappings in `nis2-ai-act-mapping.md` feed evidence into Compass. |
| **IRFlow** | Optional consumer of VertGuard's webhook stream — a `BLOCKED` scan can trigger an IRFlow playbook. |

See [citadel-integration.md](citadel-integration.md),
[threatflow-integration.md](threatflow-integration.md), and the per-module
docs for the wire-level details.

---

## Why two prompt-injection detectors (rule + ML)?

The rule-based detector is **deterministic, auditable, and cheap**
(<2 ms p50). It catches known jailbreak patterns and is the right
default for environments where regulators want to inspect the
decision logic.

The ML detector is **broader but less explainable** (~38 ms p50 on
CPU). It catches paraphrased jailbreaks the rule corpus has not seen
yet.

The recommended production configuration is **hybrid** — rules first
for hard blocks; the ML detector adds a `SUSPICIOUS` flag on
borderline inputs. See [module-3-prompt-injection.md](module-3-prompt-injection.md).

---

## What confidence scale does VertGuard use?

Every scan emits a `confidence ∈ [0.0, 1.0]` *for the chosen
classification*, not a probability of maliciousness.

- `CLEAN` with confidence 0.95 → "very confident this is clean"
- `BLOCKED` with confidence 0.55 → "more likely malicious than not,
  but not high-confidence"

A classification + confidence pair is therefore inseparable; never
threshold on confidence alone.

---

## How is privacy preserved when content is sensitive?

Three concentric defences:

1. **Schema-level** — no raw-content columns (see
   [data-model.md](data-model.md)).
2. **Hash-only persistence** — every scan stores SHA-256 of the input.
   Replay-detection works without the input ever leaving the caller's
   process boundary.
3. **CITADEL WORM** — audit events are hashed onto an external chain
   so a compromised VertGuard cannot rewrite history.

If the calling application needs to *re-display* the input later,
that is its responsibility — VertGuard cannot help.

---

## Can VertGuard run without CITADEL or Redis?

Yes — both are optional.

- Set `VERTGUARD_CITADEL_API_URL=""` to disable governance. Suitable
  for development. Mutations still execute; WORM emission becomes a
  no-op. **Do not deploy this configuration in production.**
- Leave `VERTGUARD_REDIS_URL` empty to disable caching. JWT denylist
  lookups will hit PostgreSQL on every request, which is measurable but
  acceptable below ~500 rps.

PostgreSQL is mandatory.

---

## How are model regressions caught before they ship?

`make test-all` runs the ML accuracy suite (`python/tests/`). Models
that regress more than 2 percentage points on the held-out validation
F1 fail the build. The corpus is curated under [false-positive-handling.md](false-positive-handling.md).

Production rollouts are staged: a new model is registered as
`shadow` first, runs alongside the current model with results
compared but not enforced, and is promoted to `live` only after the
shadow window confirms parity.

---

## How do I add a new prompt-injection rule?

```bash
# 1. Add the rule to the corpus
edit internal/prompt/corpus/jailbreak.yaml

# 2. Add a positive + negative test case
edit internal/prompt/prompt_test.go

# 3. Run the suite
make test

# 4. Submit a PR — CI re-runs accuracy gates
```

The corpus is loaded at startup; rolling restart applies the change.
For an emergency hotfix without a deploy, push the rule via the
threat-feed endpoint:

```bash
curl -X POST http://localhost:8093/api/v1/threats/iocs \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"pattern_value":"...","atlas_technique":"AML.T0051","confidence":0.9}'
```

---

## What MITRE ATLAS techniques does VertGuard cover?

Module 3 + Module 4 cooperatively cover the *Initial Access* and
*Defense Evasion* tactics for ML systems. The full list with
per-technique evidence sources lives in
[mitre-atlas-mapping.md](mitre-atlas-mapping.md).

---

## How is VertGuard licensed?

Apache-2.0, same as the rest of opensecstack. See `LICENSE` in the
project root. Embedded ML models ship under their original licences,
documented in `python/models/<model>/MODEL_CARD.md`.

---

## How do I report a security issue?

See [SECURITY.md](../SECURITY.md). **Do not** open a public GitHub
issue for a vulnerability — email `security@opensecstack.org` with
PGP-encrypted contents.

---

## Where do I go next?

- New here? Start with [quick-start.md](quick-start.md).
- Building an integration? Read
  [api.md](api.md) + [threatflow-integration.md](threatflow-integration.md).
- Operating in production? Read [operator-handbook.md](operator-handbook.md)
  and [operator-runbook.md](operator-runbook.md).
- Investigating an incident? Read
  [troubleshooting.md](troubleshooting.md) first.
- Curious about the schema? Read [data-model.md](data-model.md).
