"""Ingester for the JailbreakBench harmful-behaviors dataset.

Source: https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors
Paper:  https://arxiv.org/abs/2404.01318
License: MIT (see LICENSE-NOTICE.md in this directory).

The "behaviors" config contains 100 harmful behaviors + 100 benign
controls. We emit:
    - rows tagged "harmful"  -> expected = BLOCKED
    - rows tagged "benign"   -> expected = CLEAN

Each emitted sample's `text` is the `Behavior` field; `notes` carries
the `Goal` field plus the `Category` and `Source` upstream metadata.

Run:
    python -m training.data.ingest.jailbreakbench \\
        --output internal/prompt/corpus/corpus.jsonl --max 200
"""

from __future__ import annotations

import argparse
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

DATASET_ID = "JailbreakBench/JBB-Behaviors"
SOURCE_URL = "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors"
SOURCE_TAG = "public:jailbreakbench"


def _row_to_sample(idx: int, row: dict) -> dict | None:
    behavior = normalize(row.get("Behavior") or row.get("behavior") or "")
    if not behavior:
        return None
    goal = normalize(row.get("Goal") or row.get("goal") or "")
    category = (row.get("Category") or row.get("category") or "").strip()
    upstream_src = (row.get("Source") or row.get("source") or "").strip()
    label = (row.get("label") or row.get("Label") or "").strip().lower()
    # JBB-Behaviors splits are "harmful" and "benign"; the type field
    # is sometimes carried as `label` or via the split name. Caller
    # passes label explicitly in `_ingest`; respect it if present.
    expected = "BLOCKED" if label != "benign" else "CLEAN"
    sid = make_id("jbb", idx, behavior)
    tags = [SOURCE_TAG, "LLM01"]
    if category:
        tags.append(f"category:{category}")
    if label:
        tags.append(f"label:{label}")
    return {
        "id": sid,
        "text": behavior,
        "expected": expected,
        "context": "default",
        "source": SOURCE_TAG,
        "tags": tags,
        "notes": (f"goal={goal} | upstream_src={upstream_src}").strip(" |"),
    }


def _load_split(datasets_mod, split: str, revision: str | None):
    """Load JBB-Behaviors[behaviors] for a given split (harmful|benign)."""
    return datasets_mod.load_dataset(
        DATASET_ID, "behaviors", split=split, revision=revision
    )


def ingest(output, max_samples: int, seed: int, append: bool,
           revision: str | None) -> int:
    datasets_mod = require_datasets()
    raw_rows: list[dict] = []
    for split_name, label in (("harmful", "harmful"), ("benign", "benign")):
        try:
            ds = _load_split(datasets_mod, split_name, revision)
        except Exception as e:
            print(f"[ingest] WARN: split={split_name} unavailable: {e}",
                  file=sys.stderr)
            continue
        for r in iter_to_list(ds):
            r.setdefault("label", label)
            raw_rows.append(r)
    raw_count = len(raw_rows)
    sampled = take_sample(raw_rows, max_samples, seed)
    samples = []
    for i, row in enumerate(sampled):
        s = _row_to_sample(i, row)
        if s:
            samples.append(s)
    written = write_jsonl(output, samples, append=append)
    log_provenance(
        source_url=SOURCE_URL,
        dataset_id=DATASET_ID,
        revision=revision,
        raw_count=raw_count,
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
