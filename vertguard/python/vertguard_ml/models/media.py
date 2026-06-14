"""Sklearn gradient-boosting media authenticity backend.

Phase 4.2 — requires a trained ``model.joblib`` at
``VERTGUARD_ML_MEDIA_MODEL_DIR`` (default
``/var/lib/vertguard/models/media-clip``). The directory must also
contain a ``version.txt`` written by ``training/train.py``.

Detection approach:
  Lightweight gradient-boosted ensemble over five metadata signals
  (no raw pixel inference — privacy-by-design: only hashes and metadata
  cross the gRPC boundary). C2PA provenance signals are applied as hard
  overrides after the model score to reflect their high evidential value.

  Feature vector order (must match training/train.py):
    [has_c2pa_manifest, c2pa_signature_valid, file_size_mb,
     mime_is_video, mime_is_image]

If the directory or ``model.joblib`` is missing, instantiation raises
``FileNotFoundError`` so operators who set
``VERTGUARD_ML_BACKEND=media`` without deploying weights fail loudly
rather than silently degrade.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import numpy as np

from vertguard_ml.models.base import (
    Feature,
    IdentityFeatures,
    MediaFeatures,
    Model,
    ScoreResult,
    classify,
    clamp,
)

DEFAULT_MEDIA_MODEL_DIR = "/var/lib/vertguard/models/media-clip"

# C2PA override thresholds — cap/floor applied after model score.
_C2PA_VALID_CAP = 0.15    # strong provenance: cap confidence here
_C2PA_INVALID_FLOOR = 0.70  # tampered manifest: floor confidence here


class MediaModel(Model):
    """Sklearn gradient-boosting media authenticity backend.

    Phase 4.2 implementation. Loads a pre-trained
    ``GradientBoostingClassifier`` from ``model.joblib`` in the model
    directory and scores media items from their metadata signals only.
    """

    name = "vertguard-media-clip"
    backend = "sklearn-cpu"
    training_summary = (
        "Gradient-boosted ensemble (sklearn GradientBoostingClassifier) "
        "trained on Fakeddit + DFDC metadata signals. See "
        "training/configs/media_clip.yaml for hyperparameters and "
        "model_card.yaml in the model directory for eval metrics."
    )

    def __init__(self, weights_path: str | None = None) -> None:
        try:
            import joblib
        except ImportError as e:  # pragma: no cover
            raise NotImplementedError(
                "MediaModel backend requires joblib: "
                "pip install scikit-learn  (includes joblib)"
            ) from e

        media_dir = weights_path or os.environ.get(
            "VERTGUARD_ML_MEDIA_MODEL_DIR", DEFAULT_MEDIA_MODEL_DIR
        )
        self._clf: Any = self._load(media_dir, joblib)
        self.version = self._read_version(media_dir)

    @staticmethod
    def _load(directory: str, joblib: Any) -> Any:
        path = Path(directory)
        if not path.exists():
            raise FileNotFoundError(
                f"Media ML model directory not found: {directory}. "
                "Train via `python -m training.train --config "
                "training/configs/media_clip.yaml` or set "
                "VERTGUARD_ML_MEDIA_MODEL_DIR."
            )
        model_file = path / "model.joblib"
        if not model_file.exists():
            raise FileNotFoundError(
                f"Media ML model file not found: {model_file}. "
                "Train via `python -m training.train --config "
                "training/configs/media_clip.yaml` or set "
                "VERTGUARD_ML_MEDIA_MODEL_DIR."
            )
        return joblib.load(str(model_file))

    @staticmethod
    def _read_version(directory: str) -> str:
        version_file = Path(directory) / "version.txt"
        if not version_file.exists():
            return "v0-unversioned"
        try:
            return version_file.read_text(encoding="utf-8").strip() or "v0-unversioned"
        except Exception:
            return "v0-unversioned"

    def score_prompt(self, text: str, context: str = "") -> ScoreResult:
        raise NotImplementedError("MediaModel does not score prompts.")

    def score_phishing(self, text: str, kind: str = "") -> ScoreResult:
        raise NotImplementedError("MediaModel does not score phishing.")

    def score_media(self, features: MediaFeatures) -> ScoreResult:
        start = time.perf_counter()

        # --- Build feature vector (order must match training/train.py) ---
        has_manifest = 1.0 if features.has_c2pa_manifest else 0.0
        sig_valid = 1.0 if features.c2pa_signature_valid else 0.0
        file_size_mb = features.file_size / (1024.0 * 1024.0)
        mime_lower = features.mime_type.lower()
        mime_is_video = 1.0 if mime_lower.startswith("video/") else 0.0
        mime_is_image = 1.0 if mime_lower.startswith("image/") else 0.0

        feat_vec = np.array(
            [has_manifest, sig_valid, file_size_mb, mime_is_video, mime_is_image],
            dtype=np.float64,
        )

        # --- Model inference (P(synthetic/manipulated)) ---
        raw_confidence: float = float(
            self._clf.predict_proba([feat_vec])[0][1]
        )

        # --- C2PA hard overrides ---
        # Valid manifest is strong provenance evidence → cap risk.
        # Invalid manifest is a tampering signal → floor risk.
        if features.has_c2pa_manifest and features.c2pa_signature_valid:
            confidence = clamp(min(raw_confidence, _C2PA_VALID_CAP))
        elif features.has_c2pa_manifest and not features.c2pa_signature_valid:
            confidence = clamp(max(raw_confidence, _C2PA_INVALID_FLOOR))
        else:
            confidence = clamp(raw_confidence)

        # --- Compose explainability features ---
        fired: list[Feature] = []

        if features.has_c2pa_manifest and features.c2pa_signature_valid:
            fired.append(Feature(name="c2pa_valid_manifest", weight=round(_C2PA_VALID_CAP - confidence, 4)))
        elif features.has_c2pa_manifest and not features.c2pa_signature_valid:
            fired.append(Feature(name="c2pa_invalid_signature", weight=0.50))
        else:
            fired.append(Feature(name="no_c2pa_manifest", weight=0.25))

        if mime_is_video:
            fired.append(Feature(name="mime_is_video", weight=round(float(feat_vec[3]), 4)))
        elif mime_is_image:
            fired.append(Feature(name="mime_is_image", weight=round(float(feat_vec[4]), 4)))

        if file_size_mb > 10.0:
            fired.append(Feature(name="large_file", weight=round(min(file_size_mb / 100.0, 0.20), 4)))

        fired.append(Feature(name="model_raw_score", weight=round(raw_confidence, 4)))

        fired.sort(key=lambda f: f.weight, reverse=True)

        latency_ms = (time.perf_counter() - start) * 1000.0
        return ScoreResult(
            confidence=confidence,
            verdict=classify(confidence),
            top_features=fired[:3],
            latency_ms=latency_ms,
            model_version=self.version,
            backend=self.backend,
            input_hash=features.file_hash,
        )

    def score_identity(self, features: IdentityFeatures) -> ScoreResult:
        raise NotImplementedError(
            "Identity ML head not loaded. Phase 4.3 weights required at "
            "VERTGUARD_ML_IDENTITY_MODEL_DIR. Falling back to rule-only verdict."
        )
