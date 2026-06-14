"""Ingester for the Anthropic HH-RLHF dataset (rejected branches).

Source: https://huggingface.co/datasets/Anthropic/hh-rlhf
Paper:  https://arxiv.org/abs/2204.05862
License: MIT (see LICENSE-NOTICE.md in this directory).

The repository ships several subsets. We use the harmlessness and
helpfulness pairwise comparisons. From each example we take the first
HUMAN turn of the `rejected` branch — i.e. the user prompt that elicited
the worse response. Mapping:

    harmless-base / red-team-attempts   -> BLOCKED  (adversarial / harmful asks)
    helpful-base / helpful-online / ... -> SUSPICIOUS (rejected for helpfulness only)

The full dataset is ~160k pairs; always cap with --max. Recommended
2000 for a balanced injection into a 10k corpus.

Run:
    python -m training.data.ingest.anthropic_hh \\
        --output internal/prompt/corpus/corpus.jsonl --max 2000
"""

from __future__ import annotations

import argparse
import re
import sys

from ._common import (
    add_common_args,
    iter_to_list,
    log_provenance,
    make_id,
    normalize,
    require_datasets,
    take_sample,
    write_jsonl,
)

DATASET_ID = "Anthropic/hh-rlhf"
SOURCE_URL = "https://huggingface.co/datasets/Anthropic/hh-rlhf"
SOURCE_TAG = "public:anthropic_hh"

# data_dir -> (split_name_for_id, expected_label)
SUBSETS: list[tuple[str, str]] = [
    ("harmless-base", "BLOCKED"),
    ("red-team-attempts", "BLOCKED"),
    ("helpful-base", "SUSPICIOUS"),
    ("helpful-online", "SUSPICIOUS"),
    ("helpful-rejection-sampled", "SUSPICIOUS"),
]

_HUMAN_TURN_RE = re.compile(r"\n\nHuman:\s*(.*?)(?:\n\nAssistant:|$)", re.DOTALL)


def _first_human_turn(rejected: str) -> str:
    """Extract the first 'Human:' turn from an HH-RLHF dialogue string."""
    if not rejected:
        return ""
    m = _HUMAN_TURN_RE.search(rejected)
    if m:
        return m.group(1)
    # fallback: the first paragraph after stripping leading whitespace
    return rejected.strip().split("\n\n", 1)[0]


def _row_to_sample(idx: int, row: dict, expected: str, subset: str) -> dict | None:
    rejected = row.get("rejected") or ""
    # Some HH variants (red-team-attempts) use a different schema with
    # `transcript` and a `task_description` instead of chosen/rejected.
    if not rejected:
        rejected = row.get("transcript") or ""
    text = normalize(_first_human_turn(rejected))
    if not text or len(text) < 8:
        return None
    sid = make_id(f"hh_{subset}", idx, text)
    tags = [SOURCE_TAG, f"subset:{subset}"]
    if expected == "BLOCKED":
        tags.append("harmful_request")
    return {
        "id": sid,
        "text": text,
        "expected": expected,
        "context": "default",
        "source": SOURCE_TAG,
        "tags": tags,
        "notes": f"subset={subset} branch=rejected.first_human",
    }


def ingest(output, max_samples: int, seed: int, append: bool,
           revision: str | None) -> int:
    datasets_mod = require_datasets()
    # Per-subset budget so we don't drown one class.
    per_subset = max(1, max_samples // len(SUBSETS)) if max_samples > 0 else 0
    raw_total = 0
    samples: list[dict] = []
    for subset, expected in SUBSETS:
        try:
            ds = datasets_mod.load_dataset(
                DATASET_ID, data_dir=subset, split="train", revision=revision
            )
        except Exception as e:
            print(f"[ingest] WARN: subset={subset} unavailable: {e}",
                  file=sys.stderr)
            continue
        rows = iter_to_list(ds)
        raw_total += len(rows)
        sampled = take_sample(rows, per_subset, seed) if per_subset else rows
        for i, row in enumerate(sampled):
            s = _row_to_sample(i, row, expected, subset)
            if s:
                samples.append(s)
    written = write_jsonl(output, samples, append=append)
    log_provenance(
        source_url=SOURCE_URL,
        dataset_id=DATASET_ID,
        revision=revision,
        raw_count=raw_total,
        written=written,
        output=output,
    )
    return written


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_common_args(p)
    args = p.parse_args()
    n = ingest(args.output, args.max, args.seed, args.append, args.revision)
    print(f"wrote {n} new samples to {args.output}")


if __name__ == "__main__":
    main()
