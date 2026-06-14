"""Evaluate a checkpoint against the labelled corpus.

Output JSON shape mirrors internal/prompt/corpus/corpus.go's Report so the
Go-side and Python-side dashboards can share the same renderer.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("vertguard.eval")

VERDICTS = ["CLEAN", "SUSPICIOUS", "BLOCKED"]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Evaluate a checkpoint against the corpus.")
    p.add_argument("--checkpoint", required=True, type=Path)
    p.add_argument("--corpus", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--num-labels", type=int, default=3)
    return p.parse_args(argv)


def _snippet(text: str, n: int = 80) -> str:
    return text if len(text) <= n else text[: n - 3] + "..."


def build_report(
    samples: list[dict[str, Any]],
    predict: Callable[[str], int],
    num_labels: int = 3,
) -> dict[str, Any]:
    """Pure logic; takes a predictor callable so tests can stub the model."""
    from .data.loader import ID_TO_LABEL, LABEL_TO_ID

    if num_labels == 2:
        id_to_label = {0: "CLEAN", 1: "BLOCKED"}
        labels = ["CLEAN", "BLOCKED"]
    else:
        id_to_label = ID_TO_LABEL
        labels = VERDICTS

    by_expected: dict[str, int] = {v: 0 for v in labels}
    confusion: dict[str, dict[str, int]] = {v: {w: 0 for w in labels} for v in labels}
    misclassified: list[dict[str, Any]] = []

    for s in samples:
        expected = s["expected"]
        if num_labels == 2 and expected != "CLEAN":
            expected = "BLOCKED"
        if expected not in by_expected:
            continue
        by_expected[expected] += 1
        pred_id = predict(s["text"])
        actual = id_to_label.get(int(pred_id), "CLEAN")
        confusion[expected][actual] += 1
        if actual != expected:
            misclassified.append(
                {
                    "id": s.get("id", ""),
                    "expected": expected,
                    "actual": actual,
                    "snippet": _snippet(s["text"]),
                }
            )

    precision: dict[str, float] = {}
    recall: dict[str, float] = {}
    f1: dict[str, float] = {}
    macro_sum = 0.0
    macro_n = 0
    for v in labels:
        tp = confusion[v][v]
        fn = sum(confusion[v][o] for o in labels if o != v)
        fp = sum(confusion[o][v] for o in labels if o != v)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        precision[v] = prec
        recall[v] = rec
        f1[v] = f
        if by_expected[v] > 0:
            macro_sum += f
            macro_n += 1

    macro_f1 = macro_sum / macro_n if macro_n else 0.0
    misclassified.sort(key=lambda m: str(m["id"]))
    top10 = misclassified[:10]

    return {
        "total": sum(by_expected.values()),
        "by_expected": by_expected,
        "confusion": confusion,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "macro_f1": macro_f1,
        "misclassified": top10,
        "labels": labels,
        "_label_map": {v: LABEL_TO_ID.get(v, -1) for v in labels},
    }


def render_markdown(report: dict[str, Any]) -> str:
    labels = report["labels"]
    lines = [
        f"# Eval report (n={report['total']}, macro_f1={report['macro_f1']:.3f})",
        "",
        "| label | P | R | F1 | n |",
        "|-------|---|---|----|---|",
    ]
    for v in labels:
        lines.append(
            f"| {v} | {report['precision'][v]:.3f} | {report['recall'][v]:.3f} "
            f"| {report['f1'][v]:.3f} | {report['by_expected'][v]} |"
        )
    lines.append("")
    lines.append(f"Top-{len(report['misclassified'])} misclassifications:")
    for m in report["misclassified"]:
        lines.append(f"- `{m['id']}` exp={m['expected']} got={m['actual']}: {m['snippet']}")
    return "\n".join(lines)


def _load_samples(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            out.append(json.loads(line))
    return out


def _hf_predictor(checkpoint: Path) -> Callable[[str], int]:
    import torch  # type: ignore
    from transformers import (  # type: ignore
        AutoModelForSequenceClassification,
        AutoTokenizer,
    )

    tok = AutoTokenizer.from_pretrained(str(checkpoint))
    model = AutoModelForSequenceClassification.from_pretrained(str(checkpoint))
    model.eval()

    def _predict(text: str) -> int:
        with torch.no_grad():
            enc = tok(text, truncation=True, padding=True, max_length=256, return_tensors="pt")
            logits = model(**enc).logits
            return int(torch.argmax(logits, dim=-1).item())

    return _predict


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = _parse_args(argv)
    samples = _load_samples(args.corpus)
    predict = _hf_predictor(args.checkpoint)
    report = build_report(samples, predict, num_labels=args.num_labels)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(render_markdown(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
