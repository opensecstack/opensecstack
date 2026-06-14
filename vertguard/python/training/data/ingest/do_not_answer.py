"""Ingester for the Do-Not-Answer dataset (LibrAI/do-not-answer).

Source: https://huggingface.co/datasets/LibrAI/do-not-answer
Paper:  https://arxiv.org/abs/2308.13387
License: Apache-2.0 (see LICENSE-NOTICE.md in this directory).

Every row in this dataset is, by construction, a question a responsible
model SHOULD refuse — so we map every row to expected=BLOCKED. The
upstream `risk_area`, `types_of_harm`, and `specific_harms` fields are
preserved as tags so trainers can stratify by harm category.

Run:
    python -m training.data.ingest.do_not_answer \\
        --output internal/prompt/corpus/corpus.jsonl --max 939
"""

from __future__ import annotations

import argparse
import re

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

DATASET_ID = "LibrAI/do-not-answer"
SOURCE_URL = "https://huggingface.co/datasets/LibrAI/do-not-answer"
SOURCE_TAG = "public:do_not_answer"

_TAG_SAFE = re.compile(r"[^a-zA-Z0-9_:.\-]+")


def _tagify(prefix: str, value: str) -> str | None:
    if not value:
        return None
    v = _TAG_SAFE.sub("_", value.strip().lower()).strip("_")
    if not v:
        return None
    return f"{prefix}:{v}"


def _row_to_sample(idx: int, row: dict) -> dict | None:
    text = normalize(row.get("question") or row.get("Question") or "")
    if not text:
        return None
    sid = make_id("dna", idx, text)
    tags = [SOURCE_TAG, "harmful_request"]
    for prefix, key in (
        ("risk", "risk_area"),
        ("harm", "types_of_harm"),
        ("specific", "specific_harms"),
    ):
        t = _tagify(prefix, str(row.get(key, "")))
        if t:
            tags.append(t)
    notes_parts = []
    for k in ("risk_area", "types_of_harm", "specific_harms", "id"):
        if row.get(k):
            notes_parts.append(f"{k}={row[k]}")
    return {
        "id": sid,
        "text": text,
        "expected": "BLOCKED",
        "context": "default",
        "source": SOURCE_TAG,
        "tags": tags,
        "notes": " | ".join(notes_parts),
    }


def ingest(output, max_samples: int, seed: int, append: bool,
           revision: str | None) -> int:
    datasets_mod = require_datasets()
    ds = datasets_mod.load_dataset(DATASET_ID, revision=revision)
    # Dataset has a single "train" split (939 rows as of 2023-08).
    split_name = "train" if "train" in ds else list(ds.keys())[0]
    rows = iter_to_list(ds[split_name])
    raw_count = len(rows)
    sampled = take_sample(rows, max_samples, seed)
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
