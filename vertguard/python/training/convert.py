"""PyTorch checkpoint -> ONNX export for production inference."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

logger = logging.getLogger("vertguard.convert")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export a HF checkpoint to ONNX.")
    p.add_argument("--checkpoint", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--opset", type=int, default=14)
    p.add_argument("--max-seq-len", type=int, default=256)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = _parse_args(argv)

    import numpy as np  # type: ignore
    import onnx  # type: ignore
    import onnxruntime as ort  # type: ignore
    import torch  # type: ignore
    from transformers import (  # type: ignore
        AutoModelForSequenceClassification,
        AutoTokenizer,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    onnx_path = args.output_dir / "model.onnx"

    tokenizer = AutoTokenizer.from_pretrained(str(args.checkpoint))
    model = AutoModelForSequenceClassification.from_pretrained(str(args.checkpoint))
    model.eval()

    sample = tokenizer(
        "sample text for tracing",
        return_tensors="pt",
        padding="max_length",
        truncation=True,
        max_length=args.max_seq_len,
    )
    dummy_inputs = (sample["input_ids"], sample["attention_mask"])

    torch.onnx.export(
        model,
        dummy_inputs,
        str(onnx_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits": {0: "batch"},
        },
        opset_version=args.opset,
        do_constant_folding=True,
    )

    onnx.checker.check_model(str(onnx_path))

    # Round-trip: torch logits vs onnxruntime logits must agree.
    with torch.no_grad():
        torch_logits = model(**sample).logits.cpu().numpy()
    sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    ort_logits = sess.run(
        None,
        {
            "input_ids": sample["input_ids"].cpu().numpy(),
            "attention_mask": sample["attention_mask"].cpu().numpy(),
        },
    )[0]
    diff = float(np.max(np.abs(torch_logits - ort_logits)))
    logger.info("max-abs-diff torch vs onnx: %.6f", diff)
    if diff >= 1e-3:
        raise RuntimeError(f"ONNX round-trip diverged: {diff} >= 1e-3")

    tokenizer.save_pretrained(str(args.output_dir))
    print(f"ONNX export OK: {onnx_path} (max-abs-diff={diff:.2e})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
