"""DistilBERT backend.

Loads a fine-tuned `AutoModelForSequenceClassification` from a local
directory (env: VERTGUARD_ML_MODEL_DIR, default
`/var/lib/vertguard/models/distilbert-prompt`). The directory must
contain the standard transformers artefacts: `config.json`,
`model.safetensors`, `tokenizer.json` (or `vocab.txt`), plus the
`model_card.yaml` written by `training/train.py`.

If the directory is missing or unloadable, instantiation raises so
operators who flip `VERTGUARD_ML_BACKEND=distilbert` without a model
fail loudly rather than silently degrade. Phase 4.2 default remains the
stub backend.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from vertguard_ml.models.base import (
    Feature,
    IdentityFeatures,
    MediaFeatures,
    Model,
    ScoreResult,
    classify,
    hash_input,
)

# Mirrors training/data/loader.py LABEL_TO_ID. Keep in sync.
ID_TO_LABEL = {0: "CLEAN", 1: "SUSPICIOUS", 2: "BLOCKED"}

DEFAULT_MODEL_DIR = "/var/lib/vertguard/models/distilbert-prompt"
DEFAULT_PHISHING_MODEL_DIR = "/var/lib/vertguard/models/distilbert-phishing"


class DistilBertModel(Model):
    name = "distilbert-prompt-injection"
    backend = "torch-cpu"
    training_summary = (
        "Fine-tuned DistilBERT 3-class classifier (CLEAN/SUSPICIOUS/BLOCKED) "
        "on internal/prompt/corpus/corpus.jsonl. See model_card.yaml in the "
        "model directory for hyperparameters, dataset hash, and eval metrics."
    )

    def __init__(
        self,
        weights_path: str | None = None,
        phishing_weights_path: str | None = None,
        max_seq_len: int = 256,
    ) -> None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as e:  # pragma: no cover
            raise NotImplementedError(
                "DistilBERT backend requires the [ml] extra: "
                "pip install vertguard-ml[ml]"
            ) from e

        self._torch = torch
        self.max_seq_len = max_seq_len

        prompt_dir = weights_path or os.environ.get(
            "VERTGUARD_ML_MODEL_DIR", DEFAULT_MODEL_DIR
        )
        phishing_dir = phishing_weights_path or os.environ.get(
            "VERTGUARD_ML_PHISHING_MODEL_DIR", DEFAULT_PHISHING_MODEL_DIR
        )

        self._prompt_tokenizer, self._prompt_model = self._load(
            prompt_dir, AutoTokenizer, AutoModelForSequenceClassification
        )
        self.version = self._read_version(prompt_dir)
        self.eval_metrics_json = self._read_eval_metrics(prompt_dir)

        # Phishing head is optional: if its directory doesn't exist the
        # backend still serves prompt-injection. score_phishing then
        # raises a clear error instead of returning bogus output.
        if Path(phishing_dir).exists():
            self._phish_tokenizer, self._phish_model = self._load(
                phishing_dir, AutoTokenizer, AutoModelForSequenceClassification
            )
        else:
            self._phish_tokenizer = None
            self._phish_model = None

    @staticmethod
    def _load(directory: str, tok_cls: Any, model_cls: Any) -> tuple[Any, Any]:
        path = Path(directory)
        if not path.exists():
            raise FileNotFoundError(
                f"DistilBERT model directory not found: {directory}. "
                "Train via `python -m training.train` or override "
                "VERTGUARD_ML_MODEL_DIR."
            )
        tokenizer = tok_cls.from_pretrained(str(path))
        model = model_cls.from_pretrained(str(path))
        model.eval()
        return tokenizer, model

    @staticmethod
    def _read_version(directory: str) -> str:
        card = Path(directory) / "model_card.yaml"
        if not card.exists():
            return "v0-uncarded"
        try:
            import yaml  # local import: yaml is in [training], not [ml]

            with open(card, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            return str(doc.get("model", {}).get("version", "v0-uncarded"))
        except Exception:
            return "v0-uncarded"

    @staticmethod
    def _read_eval_metrics(directory: str) -> str:
        card = Path(directory) / "model_card.yaml"
        if not card.exists():
            return "{}"
        try:
            import json
            import yaml

            with open(card, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            return json.dumps(doc.get("eval", {}), separators=(",", ":"))
        except Exception:
            return "{}"

    def _infer(
        self, tokenizer: Any, model: Any, text: str, context: str = ""
    ) -> ScoreResult:
        torch = self._torch
        start = time.perf_counter()
        encoded = tokenizer(
            text,
            truncation=True,
            padding="max_length",
            max_length=self.max_seq_len,
            return_tensors="pt",
        )
        with torch.no_grad():
            logits = model(**encoded).logits
            probs = torch.softmax(logits, dim=-1).squeeze(0).tolist()
        idx = int(max(range(len(probs)), key=lambda i: probs[i]))
        verdict = ID_TO_LABEL.get(idx, "CLEAN")
        confidence = float(probs[idx])

        # Compose a "risk" scalar that the Go scorer can fold without
        # knowing class layout: P(BLOCKED) + 0.5*P(SUSPICIOUS).
        risk = float(probs[2]) + 0.5 * float(probs[1]) if len(probs) >= 3 else confidence
        # Keep the verdict the model actually predicted (argmax) but
        # report `confidence` as the risk scalar in [0,1] so Go-side
        # threshold folding still works for callers that ignore verdict.
        latency_ms = (time.perf_counter() - start) * 1000.0
        top = [Feature(name=f"P({label})", weight=float(probs[i]))
               for i, label in ID_TO_LABEL.items() if i < len(probs)]
        top.sort(key=lambda f: f.weight, reverse=True)
        return ScoreResult(
            confidence=risk,
            verdict=verdict if verdict != "CLEAN" else classify(risk),
            top_features=top,
            latency_ms=latency_ms,
            model_version=self.version,
            backend=self.backend,
            input_hash=hash_input(text),
        )

    def score_prompt(self, text: str, context: str = "") -> ScoreResult:
        return self._infer(self._prompt_tokenizer, self._prompt_model, text, context)

    def score_phishing(self, text: str, kind: str = "") -> ScoreResult:
        if self._phish_model is None:
            raise NotImplementedError(
                "Phishing DistilBERT head not loaded. Train via "
                "`python -m training.train --config training/configs/"
                "distilbert_phishing.yaml` and set "
                "VERTGUARD_ML_PHISHING_MODEL_DIR."
            )
        return self._infer(self._phish_tokenizer, self._phish_model, text, kind)

    def score_media(self, features: MediaFeatures) -> ScoreResult:
        # Phase 4.2: media ML head not yet trained. Raise clearly so
        # the Go soft-fail path falls back to C2PA-only verdict.
        raise NotImplementedError(
            "Media ML head not loaded. Phase 4.2 weights required at "
            "VERTGUARD_ML_MEDIA_MODEL_DIR. Falling back to C2PA-only verdict."
        )

    def score_identity(self, features: IdentityFeatures) -> ScoreResult:
        raise NotImplementedError(
            "Identity ML head not loaded. Phase 4.3 weights required at "
            "VERTGUARD_ML_IDENTITY_MODEL_DIR. Falling back to rule-only verdict."
        )
