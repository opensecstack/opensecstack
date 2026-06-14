"""Loads the labelled prompt-injection corpus into a HuggingFace Dataset."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Verdict enum mirrors internal/prompt/corpus/corpus.go. CLEAN=0 keeps the
# benign class as the default so binary-task variants can drop SUSPICIOUS/BLOCKED
# into a single positive class without renumbering.
LABEL_TO_ID: dict[str, int] = {"CLEAN": 0, "SUSPICIOUS": 1, "BLOCKED": 2}
ID_TO_LABEL: dict[int, str] = {v: k for k, v in LABEL_TO_ID.items()}


def _read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {lineno}: {exc}") from exc
            for required in ("id", "text", "expected"):
                if not obj.get(required):
                    raise ValueError(f"line {lineno}: missing field {required!r}")
            if obj["expected"] not in LABEL_TO_ID:
                raise ValueError(f"line {lineno}: invalid expected {obj['expected']!r}")
            rows.append(obj)
    return rows


def load_corpus(path: str | Path) -> Any:
    """Read JSONL corpus, return a HuggingFace Dataset with normalised columns."""
    # Local import: keep this module importable without `datasets` installed,
    # so test_loader can validate parsing logic via _read_jsonl directly.
    from datasets import Dataset  # type: ignore

    rows = _read_jsonl(path)
    payload: dict[str, list[Any]] = {
        "id": [r["id"] for r in rows],
        "text": [r["text"] for r in rows],
        "label": [LABEL_TO_ID[r["expected"]] for r in rows],
        "context": [r.get("context", "default") for r in rows],
        "tags": [r.get("tags", []) for r in rows],
    }
    return Dataset.from_dict(payload)


def tokenize(ds: Any, tokenizer: Any, max_len: int = 256) -> Any:
    """Apply tokenizer in batched mode; returns dataset ready for Trainer."""

    def _tok(batch: dict[str, list[Any]]) -> dict[str, Any]:
        out = tokenizer(
            batch["text"],
            truncation=True,
            padding="max_length",
            max_length=max_len,
        )
        out["labels"] = batch["label"]
        return out

    return ds.map(_tok, batched=True, remove_columns=[c for c in ds.column_names if c != "id"])
