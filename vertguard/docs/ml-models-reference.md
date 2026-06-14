## VertGuard ML Models Reference

This document is the technical documentation required by EU AI Act
Article 11 for each ML model deployed in the VertGuard platform. It
provides one model card per deployed model, cross-referenced with the
CITADEL WORM deployment record that anchors each model card's hash at
promotion time.

Audience: compliance officers, auditors, ML engineers, and security
architects. This document is updated at every model version promotion.
The canonical source of version-specific metrics is the per-version
`model_card.yaml` in the model registry (see
[`ml-model-registry.md`](ml-model-registry.md)); this file aggregates
the human-readable cards and adds regulatory context.

Cross-references: [`ml-architecture.md`](ml-architecture.md),
[`ml-training-guide.md`](ml-training-guide.md),
[`ml-model-registry.md`](ml-model-registry.md),
[`privacy-ml-inference.md`](privacy-ml-inference.md),
[`nis2-ai-act-mapping.md`](nis2-ai-act-mapping.md).

## How to read this document

Each section below is a model card for one deployed model. Cards follow
the template defined in [`ml-training-guide.md`](ml-training-guide.md)
§Model card template and extend it with the regulatory fields required
by AI Act Article 11(1)(a)–(h) and Article 13 (transparency).

At the end of each card, the **CITADEL WORM submission** block records
the SHA-256 hash of the `model_card.yaml` artefact as it existed at
promotion time, and the WORM entry ID that anchors it. This hash is
recomputable from the registry object and must match the WORM entry to
confirm the card has not been altered since promotion.

## Versioning convention

Model identifiers follow `<name>/<semver>`. The `<name>` corresponds to
the directory name under `s3://vg-models/models/`. When multiple versions
appear in the registry, the version in `latest.txt` is the production
version; `staging.txt` is the canary candidate.

---

## Model Card 1 — Prompt Injection Classifier

### Identity

| Field             | Value                                              |
|-------------------|----------------------------------------------------|
| Model ID          | `distilbert-prompt-injection`                      |
| Version           | `v1.0.0` (first production release)                |
| Base architecture | DistilBERT (`distilbert-base-multilingual-cased`)  |
| Task              | 3-class sequence classification                    |
| Output classes    | `BLOCKED`, `SUSPICIOUS`, `CLEAN`                   |
| Serving backend   | ONNX Runtime (CPU); torch-GPU optional             |
| Deployment phase  | Phase 4.2                                          |
| Registry path     | `s3://vg-models/models/distilbert-prompt-injection/v1.0.0/` |

### Purpose

The prompt injection classifier is VertGuard's ML enrichment stage for
Module 3 (LLM prompt-injection defence). It operates exclusively on the
SUSPICIOUS band — inputs that the regex prefilter could neither confirm
as CLEAN nor confidently classify as BLOCKED. Its function is to rescue
regex false positives (SUSPICIOUS → CLEAN) and to escalate genuine
attacks that evade literal pattern matching (SUSPICIOUS → BLOCKED).

This model addresses three attack classes that regex cannot cover:

1. **Paraphrase attacks** — jailbreaks phrased to avoid canonical
   trigger strings (OWASP LLM01).
2. **Indirect / multi-step injection** — attack payload buried inside
   benign envelope text.
3. **Encoded payloads** — base64, rot13, unicode-confusable wrappers.

The model does not replace the regex prefilter. The regex prefilter
retains full authority over high-confidence BLOCKED verdicts (precision
1.00 by design). The ML stage only arbitrates the borderline band.

### Training data

| Property              | Value                                              |
|-----------------------|----------------------------------------------------|
| Primary file          | `internal/prompt/corpus/corpus.jsonl`              |
| Evaluation file       | `internal/prompt/corpus/eval.jsonl`                |
| Total samples (v1)    | 100 (35 BLOCKED, 25 SUSPICIOUS, 40 CLEAN)          |
| Languages             | English (primary), Albanian (partial coverage)     |
| Label method          | Human reviewers; two-reviewer sign-off per sample  |
| Dataset hash          | Recorded in `model_card.yaml` as `sha256:...`      |
| Corpus version        | Tracked in `internal/prompt/corpus/TUNING.md`      |

Known corpus gaps (tracked under VG-007/VG-008):

- Paraphrase and indirect attacks underrepresented (v1 corpus focuses
  on canonical OWASP LLM01/06 phrasings).
- Albanian-language coverage is partial; cross-lingual generalisation
  depends on the multilingual base model rather than labelled Albanian
  samples.
- Encoded payload variants (base64, rot13, unicode-confusable) are
  present in the red-team corpus but not yet in the main training set.

Corpus expansion plan: back-translation augmentation, opt-in community
contributions via CITADEL (submitter-side hashing), and monthly
adversarial red-team batches — see
[`ml-training-guide.md`](ml-training-guide.md) §Dataset.

### Evaluation metrics (v1.0.0)

Evaluated on the held-out `eval.jsonl` split. All three ship gates must
pass for promotion; see [`ml-training-guide.md`](ml-training-guide.md)
§Evaluation.

| Metric                | v1.0.0 result | Ship gate | Status |
|-----------------------|---------------|-----------|--------|
| Macro-F1              | 0.83          | ≥ 0.80    | PASS   |
| BLOCKED precision     | 0.96          | ≥ 0.95    | PASS   |
| BLOCKED recall        | 0.92          | ≥ 0.90    | PASS   |
| CLEAN precision       | 0.88          | —         | INFO   |
| CLEAN recall          | 0.81          | —         | INFO   |
| SUSPICIOUS F1         | 0.71          | —         | INFO   |
| Regex baseline macro-F1 | 0.30        | —         | INFO   |

The full confusion matrix and per-sample misclassification list are
attached in `artifacts/distilbert-prompt-injection/v1.0.0/eval_report.json`.

### Known limitations

- **Small training corpus.** 100 samples is below the recommended floor
  for robust generalisation. Accuracy on out-of-distribution paraphrase
  attacks may degrade faster than metrics on the current eval split
  suggest.
- **Multilingual coverage.** Albanian-language attacks rely on
  cross-lingual transfer from the base model, not from labelled Albanian
  samples. Performance on Albanian inputs is not independently validated
  in v1.
- **Adversarial robustness.** The model has not been evaluated against
  adversarial perturbation attacks (character-level substitutions,
  homoglyph replacements) beyond those in the red-team corpus.
- **Maximum sequence length 256 tokens.** Inputs longer than 256 tokens
  are truncated by the tokeniser. Attacks that place the payload beyond
  token position 256 will not be seen by the model.
- **Confidence calibration.** The reported confidence score is a softmax
  probability and is not calibrated against empirical frequency. Operators
  should not treat a confidence of 0.91 as meaning "91% of such inputs
  are attacks" — treat it as a relative ordering signal.

### Bias assessment

The v1 training corpus was constructed from internal red-team samples and
public OWASP LLM01/06 datasets. Known potential biases:

| Dimension               | Assessment                                           |
|-------------------------|------------------------------------------------------|
| Language                | English-dominant; Albanian via transfer only         |
| Attack style            | Overrepresents canonical OWASP phrasings; novel phrasings underrepresented |
| Benign content style    | CLEAN samples drawn from internal test prompts; may not reflect full diversity of production inputs |
| Domain                  | No domain-specific training (finance, medical, legal); domain-specific jailbreaks may behave differently |

Bias assessment is updated at each re-train. The ML team is responsible
for reviewing the misclassification list in `eval_report.json` for
systematic error patterns before signing off on promotion.

### Update cadence

| Trigger                              | Action                               |
|--------------------------------------|--------------------------------------|
| Monthly red-team pass with regression > 2 pp on any ship gate | Re-train; promote via registry canary flow |
| Two consecutive monthly regressions  | Sev-2 incident; immediate re-train   |
| Corpus expansion milestone (VG-007/VG-008) | Scheduled re-train             |
| New OWASP LLM Top 10 release         | Gap analysis; re-train if coverage gaps identified |

### Responsible use

This model is designed for deployment within VertGuard's gated inference
pipeline. It must not be:

- Used as a standalone classifier without the regex prefilter context.
- Applied to classify natural persons or their intentions (it classifies
  prompt text, not people).
- Relied upon as the sole control against prompt injection; defence-in-depth
  with human review remains essential.

Operators are responsible for setting the confidence thresholds
(`config.prompt.clean_threshold`, `config.prompt.block_threshold`) to
match their risk tolerance. The defaults are tuned for the general case;
high-security deployments should review these values.

### CITADEL WORM submission

At promotion from staging to production, the SHA-256 of
`model_card.yaml` is submitted to the CITADEL WORM log. This creates a
tamper-evident anchor linking the card to the promotion event.

```
model_card_sha256: sha256:<computed at promotion>
worm_entry_id:     <CITADEL WORM entry ID recorded at promotion>
promoted_by:       <ML engineer identity — four-eyes sign-off>
promoted_at:       <ISO-8601 timestamp>
promotion_gate:    staging → canary-5 → canary-50 → production
```

To verify: download `model_card.yaml` from the registry path above,
compute `sha256sum model_card.yaml`, and compare against the WORM entry.
A mismatch indicates the card was altered after promotion and must be
treated as a supply-chain integrity incident. Playbook:
[`operator-runbook.md`](operator-runbook.md) §3.10.

---

## Model Card 2 — Phishing Detector

### Identity

| Field             | Value                                              |
|-------------------|----------------------------------------------------|
| Model ID          | `distilbert-phishing`                              |
| Version           | `v1.0.0` (first production release)                |
| Base architecture | DistilBERT (`distilbert-base-multilingual-cased`)  |
| Task              | 3-class sequence classification                    |
| Output classes    | `BLOCKED`, `SUSPICIOUS`, `CLEAN`                   |
| Serving backend   | ONNX Runtime (CPU); torch-GPU optional             |
| Deployment phase  | Phase 4.2                                          |
| Registry path     | `s3://vg-models/models/distilbert-phishing/v1.0.0/` |

### Purpose

The phishing detector is the ML enrichment stage for Module 2 (AI
phishing detection). It classifies the text body of communications —
emails, messages, documents — for AI-generated phishing characteristics,
including LLM-polished lure text, synthetic urgency phrasing, and
spear-phishing personalisation patterns that evade signature-based
filters.

The model operates in the same two-stage pipeline as the prompt injection
classifier: the regex prefilter handles high-confidence detections; the
ML stage arbitrates the SUSPICIOUS band. The gRPC endpoint is
`ScorePhishing` on the `InferenceService`.

Attack classes targeted:

1. **AI-polished lure text** — grammatically correct phishing that
   defeats quality-based heuristics.
2. **Synthetic urgency and authority** — LLM-generated impersonation of
   executives, regulators, or IT helpdesks (MITRE ATLAS AML.T0043).
3. **Spear-phishing personalisation** — references to names, projects,
   or events that a generic template would not include.

### Training data

| Property              | Value                                              |
|-----------------------|----------------------------------------------------|
| Primary dataset       | Curated mix of SpamAssassin corpus (public), internal red-team phishing samples, and LLM-generated synthetic phishing text |
| Evaluation split      | Held-out 20% stratified split                      |
| Total samples (v1)    | Approx. 1,200 (400 BLOCKED, 300 SUSPICIOUS, 500 CLEAN) |
| Languages             | English (primary), partial Albanian                |
| Label method          | Two-reviewer sign-off; synthetic samples flagged with generation model and prompt template |
| Dataset hash          | Recorded in `model_card.yaml` as `sha256:...`      |

The phishing training corpus is larger than the prompt injection corpus
because public phishing datasets (SpamAssassin, PhishTank export) provide
a much larger BLOCKED class base. Synthetic LLM-generated samples were
labelled by the security team using model provenance tracking; the
generation model and prompt template are recorded in the corpus metadata.

Known corpus gaps:

- Albanian-language phishing coverage relies on cross-lingual transfer.
- Voice-clone-adjacent text patterns (CEO fraud scripts) are present but
  underrepresented relative to their prevalence in production.
- Very short messages (under 20 tokens) are poorly represented; the
  model may underperform on SMS-phishing (smishing) inputs.

### Evaluation metrics (v1.0.0)

| Metric                | v1.0.0 result | Ship gate | Status |
|-----------------------|---------------|-----------|--------|
| Macro-F1              | 0.85          | ≥ 0.80    | PASS   |
| BLOCKED precision     | 0.97          | ≥ 0.95    | PASS   |
| BLOCKED recall        | 0.91          | ≥ 0.90    | PASS   |
| CLEAN precision       | 0.90          | —         | INFO   |
| CLEAN recall          | 0.87          | —         | INFO   |
| SUSPICIOUS F1         | 0.74          | —         | INFO   |

Full evaluation report: `artifacts/distilbert-phishing/v1.0.0/eval_report.json`.

### Known limitations

- **Context-free classification.** The model classifies individual
  message bodies; it does not have access to sender reputation, domain
  age, or email header metadata. False-positive rate on legitimate
  marketing email with urgency language may be elevated.
- **Short-text degradation.** Messages under 20 tokens are truncated into
  a regime where the classifier has limited signal. Smishing and short
  in-app messages are lower confidence.
- **Evolving attack surface.** AI-generated phishing quality improves
  continuously. Red-team cadence (monthly) is the primary mitigation.
- **No URL analysis.** The model analyses text only; embedded malicious
  URLs are not extracted or resolved. URL analysis is a planned
  complementary control, not part of this model.

### Bias assessment

| Dimension               | Assessment                                           |
|-------------------------|------------------------------------------------------|
| Language                | English-dominant; Albanian via transfer              |
| Sector                  | Training mix skews toward generic consumer phishing; sector-specific (banking, healthcare) spear-phishing underrepresented |
| Message length          | Short messages underrepresented                      |
| Generation model        | LLM-synthetic samples generated with GPT-4 and Claude 3; phishing from other generation models may differ stylistically |

### Update cadence

Same cadence as the prompt injection classifier: monthly red-team pass,
re-train on regression > 2 pp, two consecutive regressions trigger Sev-2.
Additionally, any newly discovered LLM-based phishing campaign reported
via CITADEL threat intelligence triggers an unscheduled evaluation pass.

### Responsible use

The phishing detector must not be used to classify natural persons as
"phishers" — it classifies message content, not people. Enforcement
action on a detection must involve human review before account suspension
or legal escalation.

### CITADEL WORM submission

```
model_card_sha256: sha256:<computed at promotion>
worm_entry_id:     <CITADEL WORM entry ID recorded at promotion>
promoted_by:       <ML engineer identity — four-eyes sign-off>
promoted_at:       <ISO-8601 timestamp>
promotion_gate:    staging → canary-5 → canary-50 → production
```

Verification procedure: identical to Model Card 1. Mismatch triggers
supply-chain integrity incident.

---

## Model Card 3 — Identity Verifier

### Identity

| Field             | Value                                              |
|-------------------|----------------------------------------------------|
| Model ID          | `identity-verifier`                                |
| Version           | `v0.1.0` (Phase 4.4 preview; not yet in production)|
| Base architecture | Wav2Vec2 (audio head) + CLIP (image head); ensemble |
| Task              | Binary classification: `AUTHENTIC` / `SYNTHETIC`   |
| Output classes    | `AUTHENTIC`, `SYNTHETIC`                           |
| Serving backend   | torch-GPU (A10 or better required for audio head)  |
| Deployment phase  | Phase 4.4 (planned)                                |
| Registry path     | `s3://vg-models/models/identity-verifier/v0.1.0/`  |

### Purpose

The identity verifier supports Module 5 (synthetic identity fraud
detection, Phase 4.4). It classifies audio segments and/or face images
as authentic (recorded from a real person in real-time) or synthetic
(voice-cloned, deepfake video, or otherwise AI-generated). Its primary
use case is detecting CEO-fraud voice calls and synthetic-identity
document photos.

The model is composed of two independent heads:

- **Audio head** — fine-tuned Wav2Vec2 on a voice-clone detection task.
  Ingests 16kHz mono audio segments, up to 10 seconds, returns a
  per-segment AUTHENTIC/SYNTHETIC score.
- **Image head** — fine-tuned CLIP image encoder on a deepfake detection
  task. Ingests face crops (224x224 px), returns AUTHENTIC/SYNTHETIC
  score.

Ensemble fusion: the two head scores are combined with a fixed-weight
average (0.5/0.5); the combined score is thresholded at
`config.identity.block_threshold`. This is a v0.1 simplification; Phase
4.4.1 will replace the fixed ensemble with a learned meta-classifier.

The identity verifier has a separate gRPC endpoint (`ScoreIdentity`) and
runs in a dedicated GPU-required Pod. It is not deployed in the default
Helm chart; operators enable it via `modules.identity.enabled=true`.

### Training data

| Property              | Value                                              |
|-----------------------|----------------------------------------------------|
| Audio — authentic     | LibriSpeech clean-100 (public); internal speaker samples (consented) |
| Audio — synthetic     | ElevenLabs, Bark, XTTS v2 generated samples; in-house voice-clone rig |
| Image — authentic     | CelebA-HQ subset (public, research license); internal consented photos |
| Image — synthetic     | StyleGAN3, Stable Diffusion XL, InsightFace Swap outputs |
| Total audio samples   | ~8,000 segments (50/50 authentic/synthetic)        |
| Total image samples   | ~12,000 crops (50/50 authentic/synthetic)          |
| Languages (audio)     | English, Albanian, Italian (coverage uneven)       |
| Dataset hash          | Separate hashes for audio and image splits; both recorded in `model_card.yaml` |

Privacy note on training data: all authentic audio and image samples are
either from public research datasets with appropriate licenses or from
consented internal recordings. No production scan inputs were used in
training. See [`privacy-ml-inference.md`](privacy-ml-inference.md) for
the inference-time data handling policy.

Known corpus gaps:

- Albanian-language authentic audio is sparse; false-negative rate on
  Albanian voice clips is estimated to be higher than for English.
- Generation models added after the training cutoff (any model released
  post-training) will produce out-of-distribution outputs; the audio
  head is particularly sensitive to this.
- Compressed audio (phone codec artifacts, VoIP) is underrepresented;
  real-world deployments typically receive compressed audio.

### Evaluation metrics (v0.1.0)

v0.1.0 is a Phase 4.4 preview, evaluated on a held-out test set. Ship
gates for Phase 4.4 production promotion are defined below and have not
yet been met; this version is not promoted to production.

| Metric                        | v0.1.0 result | Phase 4.4 gate | Status  |
|-------------------------------|---------------|----------------|---------|
| Audio SYNTHETIC recall        | 0.82          | ≥ 0.90         | NOT MET |
| Audio SYNTHETIC precision     | 0.89          | ≥ 0.92         | NOT MET |
| Image SYNTHETIC recall        | 0.91          | ≥ 0.90         | PASS    |
| Image SYNTHETIC precision     | 0.93          | ≥ 0.92         | PASS    |
| Ensemble macro-F1             | 0.86          | ≥ 0.88         | NOT MET |
| Compressed-audio SYNTHETIC recall | 0.71      | ≥ 0.85         | NOT MET |

The audio head underperforms on compressed audio; VG-021 tracks the
corpus gap. A compressed-audio augmentation pass is planned before the
Phase 4.4 production ship.

### Known limitations

- **Generation model staleness.** The audio head was trained on voice-
  clone models available before the training cutoff. New voice-clone
  models released after the cutoff may evade detection until a re-train
  includes their outputs.
- **Liveness not verified.** The model classifies whether audio/image
  content appears synthetic; it does not perform liveness detection
  (anti-spoofing against replayed authentic recordings). Liveness
  detection is a separate control.
- **Language dependence (audio head).** Authentic/synthetic acoustic
  properties vary by language and speaker demographics; performance is
  validated primarily for English.
- **Face crop dependency (image head).** The image head requires a clean
  face crop as input; face detection is a prerequisite. Poor face
  detection (low resolution, occlusion) degrades the image head's
  reliability independently of the model quality.
- **Phone codec artefacts.** See evaluation metrics; compressed-audio
  performance is below the production gate. Do not promote for
  phone-call use cases until VG-021 is resolved.

### Bias assessment

| Dimension               | Assessment                                           |
|-------------------------|------------------------------------------------------|
| Language (audio)        | English-dominant; Albanian and Italian coverage thin |
| Speaker demographics    | LibriSpeech and CelebA-HQ skew toward certain speaker demographics; bias in SYNTHETIC recall across demographic groups not yet audited |
| Generation model coverage | Covers major English-language voice-clone tools as of training cutoff; newer or non-English-specific tools not covered |
| Image demographics      | CelebA-HQ known to over-represent certain demographics; this is inherited from the upstream dataset and is documented as an open risk |

A demographic bias audit for the audio head across gender and accent
groups is planned before the Phase 4.4 production gate. The image head
bias audit will reference the upstream CelebA-HQ bias documentation.

### Update cadence

The identity verifier has an accelerated update cadence compared to the
text models because the voice-clone and deepfake generation landscape
evolves faster:

| Trigger                              | Action                               |
|--------------------------------------|--------------------------------------|
| New voice-clone model identified     | Red-team evaluation within 2 weeks; re-train if recall drops > 3 pp |
| New deepfake generation technique    | Red-team evaluation within 2 weeks   |
| Monthly scheduled red-team           | As per text model cadence            |
| Phase 4.4.1 meta-classifier work     | Full re-train with new ensemble head |

### Responsible use

The identity verifier classifies audio and image content; it does not
identify individuals. It must not be used to build a database mapping
predictions to natural persons, to make automated employment or access
decisions, or in any context where a false SYNTHETIC verdict would have
legal consequences without human review.

Per [`privacy-ml-inference.md`](privacy-ml-inference.md): audio bytes
and image bytes are processed in-memory and discarded immediately after
the forward pass. No biometric templates or embeddings derived from
authentic content are stored by the inference service.

### CITADEL WORM submission

The v0.1.0 card is submitted to CITADEL WORM at staging entry (not yet
at production promotion, as the model has not passed its production
gates).

```
model_card_sha256: sha256:<computed at staging entry>
worm_entry_id:     <CITADEL WORM entry ID recorded at staging>
submitted_by:      <ML engineer identity>
submitted_at:      <ISO-8601 timestamp>
stage:             staging (not yet promoted to production)
```

When Phase 4.4 production gates are met, a second WORM submission will
be made recording the production promotion event with the then-current
`model_card.yaml` hash.

---

## AI Act Article 11 compliance index

Article 11(1) requires technical documentation before an AI system is
placed on the market, covering the points listed in Annex IV. The table
below maps Annex IV items to where each is addressed across the VertGuard
ML documentation.

| Annex IV item | Description                            | Location                                   |
|---------------|----------------------------------------|--------------------------------------------|
| (1)           | General description of the AI system  | [`ml-architecture.md`](ml-architecture.md) |
| (2)           | Description of the elements of the system and its development process | This document (model cards) + [`ml-training-guide.md`](ml-training-guide.md) |
| (3)           | Detailed information on the monitoring, functioning, and control | [`ml-architecture.md`](ml-architecture.md) §Observability + [`operator-runbook.md`](operator-runbook.md) §3.10 |
| (4)           | Description of the appropriateness of the performance metrics | This document §Evaluation metrics (per card) |
| (5)           | Detailed description of the risk management system | [`SECURITY.md`](../SECURITY.md) §Threat model |
| (6)           | Description of changes made to the system | CITADEL WORM promotion log (per deployment) |
| (7)           | EU Declaration of Conformity (where required) | Not yet issued; VertGuard operates in low-risk tier |
| (8)           | EU technical documentation retention  | Model registry object versioning + CITADEL WORM |

## Related

- [`ml-architecture.md`](ml-architecture.md) — system design
- [`ml-training-guide.md`](ml-training-guide.md) — training process and model card template
- [`ml-model-registry.md`](ml-model-registry.md) — version control and promotion flow
- [`privacy-ml-inference.md`](privacy-ml-inference.md) — inference-time data handling
- [`nis2-ai-act-mapping.md`](nis2-ai-act-mapping.md) — full regulatory mapping
- [EU AI Act Annex IV — technical documentation](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)
