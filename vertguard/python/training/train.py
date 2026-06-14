"""Fine-tune DistilBERT on the prompt-injection corpus.

Smoke-test mode (--max-steps 2 --cpu) must complete in <30s so CI can verify
wiring without a GPU. Full training is config-driven via --config.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("vertguard.train")

DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "internal/prompt/corpus/corpus.jsonl"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fine-tune DistilBERT for VertGuard.")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--max-steps", type=int, default=-1, help="override; useful for smoke runs")
    p.add_argument("--cpu", action="store_true", help="force CPU even if CUDA is available")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args(argv)


def _load_config(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _compute_metrics_factory(num_labels: int) -> Any:
    import numpy as np  # type: ignore
    from sklearn.metrics import precision_recall_fscore_support  # type: ignore

    from .data.loader import ID_TO_LABEL  # noqa: F401

    def _compute(eval_pred: Any) -> dict[str, float]:
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        p_macro, r_macro, f_macro, _ = precision_recall_fscore_support(
            labels, preds, average="macro", zero_division=0
        )
        p_per, r_per, f_per, _ = precision_recall_fscore_support(
            labels, preds, labels=list(range(num_labels)), zero_division=0
        )
        out: dict[str, float] = {
            "precision_macro": float(p_macro),
            "recall_macro": float(r_macro),
            "f1_macro": float(f_macro),
        }
        for cls in range(num_labels):
            out[f"precision_{cls}"] = float(p_per[cls])
            out[f"recall_{cls}"] = float(r_per[cls])
            out[f"f1_{cls}"] = float(f_per[cls])
        return out

    return _compute


def _corpus_sha256(path: Path) -> str:
    """SHA-256 over JSONL bytes after sorting by id, so reordering doesn't churn the hash."""
    lines: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            lines.append((obj.get("id", ""), line))
    lines.sort(key=lambda t: t[0])
    h = hashlib.sha256()
    for _, line in lines:
        h.update(line.encode("utf-8"))
        h.update(b"\n")
    return f"sha256:{h.hexdigest()}"


def _git_commit() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            cwd=str(Path(__file__).resolve().parent),
        )
        return f"git:{out.decode().strip()}"
    except Exception:
        return "git:unknown"


def _hardware_tag() -> str:
    try:
        import torch  # type: ignore

        if torch.cuda.is_available():
            return torch.cuda.get_device_name(0)
    except Exception:
        pass
    return f"CPU ({platform.processor() or platform.machine()})"


def _framework_tag() -> str:
    try:
        import torch  # type: ignore
        import transformers  # type: ignore

        return f"torch=={torch.__version__}, transformers=={transformers.__version__}"
    except Exception:
        return "unknown"


def _write_model_card(
    output_dir: Path,
    cfg: dict[str, Any],
    args: argparse.Namespace,
    metrics: dict[str, float],
    duration_seconds: float,
    corpus_path: Path,
) -> None:
    """Write model_card.yaml alongside the model artefacts."""
    model_cfg = cfg["model"]
    train_cfg = cfg["train"]
    num_labels = int(model_cfg["num_labels"])

    eval_block: dict[str, Any] = {
        "macro_f1": float(metrics.get("eval_f1_macro", 0.0)),
        "macro_precision": float(metrics.get("eval_precision_macro", 0.0)),
        "macro_recall": float(metrics.get("eval_recall_macro", 0.0)),
    }
    label_names = {0: "clean", 1: "suspicious", 2: "blocked"}
    for cls in range(num_labels):
        name = label_names.get(cls, f"class_{cls}")
        eval_block[f"{name}_precision"] = float(metrics.get(f"eval_precision_{cls}", 0.0))
        eval_block[f"{name}_recall"] = float(metrics.get(f"eval_recall_{cls}", 0.0))
        eval_block[f"{name}_f1"] = float(metrics.get(f"eval_f1_{cls}", 0.0))

    card: dict[str, Any] = {
        "model": {
            "name": "distilbert-prompt-injection"
            if num_labels == 3
            else "distilbert-phishing",
            "version": os.environ.get("VG_MODEL_VERSION", "v0.1.0-cpu-smoke"),
            "base": model_cfg["name"],
            "task": "3-class prompt-injection classifier"
            if num_labels == 3
            else "binary phishing classifier",
        },
        "training": {
            "seed": args.seed,
            "dataset_hash": _corpus_sha256(corpus_path),
            "code_version": _git_commit(),
            "hardware": _hardware_tag(),
            "framework": _framework_tag(),
            "duration_seconds": round(duration_seconds, 2),
            "max_steps": args.max_steps,
            "smoke": args.max_steps > 0,
            "hyperparameters": {
                "learning_rate": float(train_cfg.get("lr", 2e-5)),
                "batch_size": int(train_cfg.get("batch_size", 16)),
                "epochs": float(train_cfg.get("epochs", 3)),
                "weight_decay": float(train_cfg.get("weight_decay", 0.01)),
                "warmup_ratio": float(train_cfg.get("warmup_ratio", 0.1)),
                "max_seq_len": int(train_cfg.get("max_seq_len", 256)),
            },
        },
        "eval": eval_block,
        "deployment": {
            "backend": "torch-cpu",
            "expected_p95_ms_cpu": 50,
            "expected_p95_ms_gpu": 10,
        },
    }

    card_path = output_dir / "model_card.yaml"
    with open(card_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(card, fh, sort_keys=False, default_flow_style=False)
    logger.info("model_card_written path=%s", card_path)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = _parse_args(argv)
    cfg = _load_config(args.config)

    if args.cpu:
        os.environ["CUDA_VISIBLE_DEVICES"] = ""

    # Heavy imports happen here so --help and arg validation don't pay the cost.
    from transformers import (  # type: ignore
        AutoModelForSequenceClassification,
        AutoTokenizer,
        Trainer,
        TrainingArguments,
        set_seed,
    )

    from .data.augment import augment_dataset
    from .data.loader import load_corpus, tokenize
    from .data.splits import stratified_split

    set_seed(args.seed)

    model_cfg = cfg["model"]
    train_cfg = cfg["train"]
    data_cfg = cfg.get("data", {})

    num_labels = int(model_cfg["num_labels"])
    model_name = model_cfg["name"]
    max_seq_len = int(train_cfg.get("max_seq_len", 256))

    ds = load_corpus(args.corpus)
    if num_labels == 2:
        # Binary task: collapse SUSPICIOUS+BLOCKED into the malicious class.
        ds = ds.map(lambda r: {"label": 0 if r["label"] == 0 else 1})
    augment_factor = int(data_cfg.get("augment_factor", 1))
    if augment_factor > 1:
        ds = augment_dataset(ds, factor=augment_factor)

    splits = stratified_split(ds, seed=args.seed)

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    tokenized = splits.map(
        lambda batch: tokenizer(
            batch["text"], truncation=True, padding="max_length", max_length=max_seq_len
        ),
        batched=True,
    )
    tokenized = tokenized.rename_column("label", "labels")
    keep = {"input_ids", "attention_mask", "labels"}
    tokenized = tokenized.remove_columns(
        [c for c in tokenized["train"].column_names if c not in keep]
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        model_name, num_labels=num_labels
    )

    training_args = TrainingArguments(
        output_dir=str(args.output_dir),
        learning_rate=float(train_cfg.get("lr", 2e-5)),
        per_device_train_batch_size=int(train_cfg.get("batch_size", 16)),
        per_device_eval_batch_size=int(train_cfg.get("batch_size", 16)),
        num_train_epochs=float(train_cfg.get("epochs", 3)),
        weight_decay=float(train_cfg.get("weight_decay", 0.01)),
        warmup_ratio=float(train_cfg.get("warmup_ratio", 0.1)),
        max_steps=args.max_steps,
        eval_strategy="epoch" if args.max_steps < 0 else "no",
        save_strategy="epoch" if args.max_steps < 0 else "no",
        load_best_model_at_end=args.max_steps < 0,
        metric_for_best_model="f1_macro",
        seed=args.seed,
        report_to=[],
        use_cpu=args.cpu,
        logging_steps=10,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized["train"],
        eval_dataset=tokenized["validation"],
        processing_class=tokenizer,
        compute_metrics=_compute_metrics_factory(num_labels),
    )

    train_started = time.perf_counter()
    trainer.train()
    train_duration = time.perf_counter() - train_started

    metrics = trainer.evaluate(eval_dataset=tokenized["test"])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(args.output_dir))
    tokenizer.save_pretrained(str(args.output_dir))

    _write_model_card(
        output_dir=args.output_dir,
        cfg=cfg,
        args=args,
        metrics=metrics,
        duration_seconds=train_duration,
        corpus_path=args.corpus,
    )

    macro_f1 = metrics.get("eval_f1_macro", 0.0)
    # Recall for the BLOCKED class (id=2) when present, else last class.
    blocked_recall = metrics.get(f"eval_recall_{num_labels - 1}", 0.0)
    summary = f"EVAL: macro_f1={macro_f1:.2f} blocked_recall={blocked_recall:.2f}"
    print(summary)
    logger.info(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
