## Dataset expansion plan

### Where we are

| Corpus | Samples | Macro-F1 (regex) | BLOCKED precision | BLOCKED recall |
| --- | ---: | ---: | ---: | ---: |
| Prompt-injection (`internal/prompt/corpus/corpus.jsonl`) | 4016 | 0.093 | 0.994 | 0.073 |
| Phishing (`internal/phishing/corpus/corpus.jsonl`) | 115 | 0.404 | 0.75 | — |

The prompt corpus is **40×** the original 100-sample seed. The regex-only
F1 collapsed from 0.291 (885 synth) to 0.093 (4016 with public ingests):
this is the expected and instructive shape of the gap the ML layer in
Phase 4.2.1 must close. Regex precision stayed at 0.994 (no false-positive
regression); recall fell because public datasets carry phrasings that
hand-tuned regex patterns do not target.

### Composition (prompt corpus)

| Source | BLOCKED | SUSPICIOUS | CLEAN | Total |
| --- | ---: | ---: | ---: | ---: |
| Hand-curated seed (`source=synthetic` original 100) | 35 | 25 | 40 | 100 |
| Templates (`source=synthetic:templates_v1`) | 600 | 0 | 0 | 600 |
| Paraphrases (`source=synthetic:paraphrase_v1`) | 0 | 29 | 0 | 29 |
| CLEAN counter-examples (`source=synthetic:clean_v1`) | 0 | 0 | 156 | 156 |
| JailbreakBench behaviors (`source=public:jailbreakbench`) | 100 | 0 | 100 | 200 |
| Do-Not-Answer (`source=public:do_not_answer`) | 0 | 939 | 0 | 939 |
| Anthropic HH-RLHF rejected (`source=public:anthropic_hh_rlhf`) | 1732 | 260 | 0 | 1992 |
| **Total** | **2467** | **1253** | **296** | **4016** |

Public-ingest provenance (recorded at run time):
- JailbreakBench: `JailbreakBench/JBB-Behaviors`, sha256 `59117a28…b2df`
- Do-Not-Answer: `LibrAI/do-not-answer`, sha256 `f863eec6…1f04`
- HH-RLHF: `Anthropic/hh-rlhf`, 199761 raw rows sampled to 1992, sha256 `eb1b7862…b6f6`

The template generator is deterministic (seed=42). Re-running
`python -m training.data.synth.templates --max 600` reproduces the same
600 lines byte-for-byte. Same for paraphrases and clean_samples.

### Composition (phishing corpus)

115 samples, hand-curated:

| Verdict | Samples |
| --- | ---: |
| BLOCKED | 48 (URL_OBFUSCATION, BRAND_IMPERSONATION, CREDENTIAL_HARVEST, SUSPICIOUS_DOMAIN, ATTACHMENT_LURE) |
| SUSPICIOUS | 20 (legitimate-looking but borderline templates) |
| CLEAN | 47 (work emails, transactional receipts, reference URLs, multi-language) |

### Honest gap to 10k

The current 4016 + 115 corpus is **~40×** the seed and **~2.5× short** of
the Phase 4.2.1 target (10,000 samples). Reaching 10k requires:

1. **Public dataset ingestion** — ✅ partial (3131 samples landed
   2026-04-26: JBB 200, DNA 939, HH-RLHF 1992). TrustLLM skeleton
   raises until a canonical artifact is pinned. Remaining sources to
   wire: OpenAssistant safety-flagged turns, AdvBench, PromptInject.
   Each new ingester records provenance + SHA-256. We do **not
   fabricate samples**; ingesters require network and run off-sandbox.
2. **Back-translation augmentation** (~1k-2k): wire `facebook/m2m100`
   into `python/training/data/augment.py` (currently a stub). Run
   English BLOCKED through 6 pivot languages; manually filter by
   semantic preservation. Requires GPU minutes.
3. **Adversarial paraphrase mining** (~500-1k): expand the rule set in
   `paraphrases.py` from 6 rules to ~30. Each new rule needs human
   review for false-positive risk.
4. **Community labels** (~1k-2k): operators contribute via
   `internal/prompt/corpus/CONTRIBUTING.md` workflow with the 2-eyes
   review rule. Cadence: monthly batch reviews.
5. **Red-team adversarial samples** (~500): monthly red-team
   exercises by ML team produce a fresh batch of attacks the current
   classifier misses. Track in a `red_team_v<N>` source tag.

### Why not just generate 10k templates today?

The template generator can produce 1500+ samples trivially, and we
tested this — but balanced corpora matter more than raw count. The
1500-template corpus had 86% BLOCKED class skew and dropped Macro-F1
from 0.291 to 0.225 (the regex catches a fixed fraction of templates,
so adding more BLOCKED only inflates the missed-recall denominator).
We held at 600 templates → 885 total to keep the
71%/6%/22% BLOCKED/SUSPICIOUS/CLEAN distribution close to a realistic
production traffic split.

### F1 baseline locked

`internal/prompt/corpus/corpus_test.go` gates regressions at:
- Macro-F1 ≥ 0.08 (post-ingest baseline; was 0.27 pre-ingest)
- BLOCKED recall ≥ 0.06 (post-ingest baseline; was 0.25 pre-ingest)
- BLOCKED precision ≥ 0.95 (unchanged — false-positive guard)
- Sample count ≥ 3500 (drift detector for accidental deletion)

The F1 / recall floors were lowered because adding 3131 public-dataset
samples revealed the regex coverage gap. Precision held at 0.994 — the
regex remains correct on what it does flag; the ML layer is what closes
the recall side.

`internal/phishing/corpus/corpus_test.go` gates at:
- Macro-F1 ≥ 0.20
- BLOCKED precision ≥ 0.70

These are **regression detectors**, not targets. The targets land with
the ML stage in Phase 4.2.1 (Macro-F1 ≥ 0.80, BLOCKED recall ≥ 0.90).
See [`docs/ml-training-guide.md`](ml-training-guide.md) for the
training pipeline that consumes this corpus.

### Public ingesters

Three runnable ingesters + one skeleton live at
`python/training/data/ingest/`. Each downloads from a pinned
HuggingFace dataset, normalises to our schema, dedupes by ID against
the destination JSONL, and logs source URL + dataset revision +
SHA-256 of the resulting file.

Prerequisite: `pip install 'datasets>=2.18'` (already declared in the
`training` extra of `python/pyproject.toml`). Network access required.

| Module | Upstream | License | Mapping | Approx upstream rows |
| --- | --- | --- | --- | ---: |
| `jailbreakbench.py` | `JailbreakBench/JBB-Behaviors` | MIT | harmful→BLOCKED, benign→CLEAN | 200 |
| `do_not_answer.py` | `LibrAI/do-not-answer` | Apache-2.0 | all→BLOCKED | 939 |
| `anthropic_hh.py` | `Anthropic/hh-rlhf` (rejected branch, first human turn) | MIT | harmless-base/red-team→BLOCKED, helpful-*→SUSPICIOUS | ~160k (always cap) |
| `trustllm.py` | TrustLLM repo | MIT | NOT IMPLEMENTED — raises until a canonical artifact is pinned. |  — |

Commands (someone with network) to populate ~3k BLOCKED samples:

```bash
cd python
pip install -e '.[training]'
python -m training.data.ingest.jailbreakbench \
    --output ../internal/prompt/corpus/corpus.jsonl --max 200
python -m training.data.ingest.do_not_answer \
    --output ../internal/prompt/corpus/corpus.jsonl --max 939
python -m training.data.ingest.anthropic_hh \
    --output ../internal/prompt/corpus/corpus.jsonl --max 2000
```

Expected after the three: ~200 (JBB) + 939 (DNA) + 2000 (HH) = **~3.1k
new rows**, of which roughly 200×0.5 + 939 + 2000×(2/5) ≈ **1.9k
BLOCKED**, ~1.2k SUSPICIOUS, ~100 CLEAN. The exact split depends on
upstream availability of each HH subset and the random sample drawn
(seed=42 by default).

Each invocation appends and dedupes by stable ID; rerunning is
idempotent. Provenance is printed on stderr/stdout in a single
`[ingest] source_url=… dataset=… revision=… upstream_rows=N
written=M output=… sha256=…` line per run.

License notes per source live in
`python/training/data/ingest/LICENSE-NOTICE.md`. The
`source` field on every emitted row carries the `public:<name>` tag
that ties the row back to its upstream license.

### How to add samples

See `internal/prompt/corpus/CONTRIBUTING.md` (and the phishing
counterpart) for the PR workflow, label rules, and the 2-eyes review
required for BLOCKED additions.

### Reproducibility

Every synthetic generator is seeded with `42`. The corpus's SHA-256 is
recorded in `model_card.yaml` whenever a model is trained against a
specific snapshot — see `docs/ml-training-guide.md` for the model-card
template.
