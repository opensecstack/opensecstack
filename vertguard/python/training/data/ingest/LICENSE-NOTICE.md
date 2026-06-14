# Upstream license notice for ingested datasets

VertGuard's ingesters (`python/training/data/ingest/*.py`) download
public datasets at runtime and convert them to VertGuard's corpus
schema. The ingesters themselves are Apache-2.0 (matching the rest of
this repository), but anything pulled through them is governed by the
upstream license of the originating dataset.

Verify the upstream license card before redistributing the resulting
JSONL. Licenses below were observed at the time of ingester authoring
and may be updated upstream — re-check the dataset card on each pull.

## JailbreakBench (`jailbreakbench.py`)

- Dataset: https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors
- Paper:   https://arxiv.org/abs/2404.01318
- License: **MIT** (per upstream dataset card).
- Citation requirement: cite Chao et al., 2024 if used in published
  evaluations.

## Do-Not-Answer (`do_not_answer.py`)

- Dataset: https://huggingface.co/datasets/LibrAI/do-not-answer
- Paper:   https://arxiv.org/abs/2308.13387
- License: **Apache-2.0** (per upstream dataset card).
- Citation requirement: cite Wang et al., 2023.

## Anthropic HH-RLHF (`anthropic_hh.py`)

- Dataset: https://huggingface.co/datasets/Anthropic/hh-rlhf
- Paper:   https://arxiv.org/abs/2204.05862
- License: **MIT** (per upstream dataset card).
- Notes:   contains red-team transcripts. Some prompts are intentionally
  harmful; do not surface raw rejected-branch responses to end users.

## TrustLLM (`trustllm.py`) — skeleton only

- Reference: https://github.com/HowieHwong/TrustLLM
- License:   MIT (per upstream repo). **No canonical HF mirror pinned**;
  ingester intentionally raises `NotImplementedError` until a specific
  upstream artifact (raw URL + commit SHA, or a fixed HF revision) is
  selected. See module docstring.

## Mixing rules

When concatenating ingested rows into `internal/prompt/corpus/corpus.jsonl`,
each row keeps its `source: public:<name>` tag — this is the
license-traceability handle. Do NOT relabel rows with `source:
synthetic:*`, and do NOT strip the `source` field. If an upstream
license changes to one incompatible with VertGuard's redistribution,
remove rows by `source` filter rather than editing them in place.
