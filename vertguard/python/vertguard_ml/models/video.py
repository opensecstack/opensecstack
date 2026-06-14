"""Sklearn gradient-boosting video deepfake detection backend.

Phase 4.3 — requires a trained ``model.joblib`` at
``VERTGUARD_ML_VIDEO_MODEL_DIR`` (default
``/var/lib/vertguard/models/video-gan``). The directory must also
contain a ``version.txt`` written by ``training/train.py``.

Detection approach:
  Lightweight gradient-boosted ensemble over a 513-dim feature vector:
  [face_detected (0/1), *clip_embedding_512_dims (float32)]

  CLIP embeddings are extracted Go-side from raw frames and sent as
  raw float32 little-endian bytes over gRPC — no pixels cross the wire
  (privacy-by-design). The face_detected flag allows a fast-path
  early return: no face detected → no deepfake risk.

  Session temporal smoothing reduces single-frame false positives.
  A rolling window of up to 30 per-frame confidences is maintained
  per session; the final reported confidence is a weighted blend:
    0.7 * current_frame_score + 0.3 * rolling_window_mean

If the directory or ``model.joblib`` is missing, instantiation raises
``FileNotFoundError`` so operators who set
``VERTGUARD_ML_BACKEND=video`` without deploying weights fail loudly
rather than silently degrade.
"""

from __future__ import annotations

import os
import time
from collections import deque
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

DEFAULT_VIDEO_MODEL_DIR = "/var/lib/vertguard/models/video-gan"

# Embedding dimensionality — must match training/configs/video_gan.yaml.
_CLIP_DIM = 512
# Expected feature vector length: [face_detected, *clip_embedding].
_FEAT_DIM = _CLIP_DIM + 1

# Temporal smoothing weights.
_CURRENT_WEIGHT = 0.7
_ROLLING_WEIGHT = 0.3
_ROLLING_WINDOW = 30

# Confidence returned when no face is detected in the frame.
_NO_FACE_CONFIDENCE = 0.05


class VideoModel(Model):
    """Sklearn gradient-boosting video deepfake detection backend.

    Phase 4.3 implementation. Loads a pre-trained
    ``GradientBoostingClassifier`` from ``model.joblib`` in the model
    directory and scores video frames from their CLIP feature vector.

    Session-level temporal smoothing is applied in-process: a deque of
    the last 30 per-frame scores is kept per session_id and blended
    with the current frame score to reduce isolated false positives.
    """

    name = "vertguard-video-gan"
    backend = "sklearn-cpu"
    training_summary = (
        "Gradient-boosted ensemble (sklearn GradientBoostingClassifier) "
        "trained on FaceForensics++ and DFDC CLIP embeddings + face-detected "
        "flag. See training/configs/video_gan.yaml for hyperparameters and "
        "model_card.yaml in the model directory for eval metrics."
    )

    def __init__(self, weights_path: str | None = None) -> None:
        try:
            import joblib
        except ImportError as e:  # pragma: no cover
            raise NotImplementedError(
                "VideoModel backend requires joblib: "
                "pip install scikit-learn  (includes joblib)"
            ) from e

        video_dir = weights_path or os.environ.get(
            "VERTGUARD_ML_VIDEO_MODEL_DIR", DEFAULT_VIDEO_MODEL_DIR
        )
        self._clf: Any = self._load(video_dir, joblib)
        self.version = self._read_version(video_dir)
        # Per-session rolling confidence window.
        # Key: session_id; Value: deque of float confidences (maxlen=30).
        self._session_scores: dict[str, deque[float]] = {}

    @staticmethod
    def _load(directory: str, joblib: Any) -> Any:
        path = Path(directory)
        if not path.exists():
            raise FileNotFoundError(
                f"Video ML model directory not found: {directory}. "
                "Train via `python -m training.train --config "
                "training/configs/video_gan.yaml` or set "
                "VERTGUARD_ML_VIDEO_MODEL_DIR."
            )
        model_file = path / "model.joblib"
        if not model_file.exists():
            raise FileNotFoundError(
                f"Video ML model file not found: {model_file}. "
                "Train via `python -m training.train --config "
                "training/configs/video_gan.yaml` or set "
                "VERTGUARD_ML_VIDEO_MODEL_DIR."
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

    def score_frame(
        self,
        feature_vector: bytes,
        face_detected: bool,
        session_id: str,
    ) -> ScoreResult:
        """Score a single video frame for deepfake likelihood.

        Args:
            feature_vector: Raw float32 little-endian bytes of the
                512-dim CLIP embedding extracted from the frame.
            face_detected: True when a face was detected in the frame.
            session_id: Groups frames from one video call for temporal
                smoothing; passed through to the ScoreResult input_hash
                field for log correlation.

        Returns:
            ScoreResult with confidence, verdict, and latency.
        """
        start = time.perf_counter()

        # Fast-path: no face → no deepfake risk.
        if not face_detected:
            latency_ms = (time.perf_counter() - start) * 1000.0
            return ScoreResult(
                confidence=_NO_FACE_CONFIDENCE,
                verdict=classify(_NO_FACE_CONFIDENCE),
                top_features=[Feature(name="no_face_detected", weight=1.0)],
                latency_ms=latency_ms,
                model_version=self.version,
                backend=self.backend,
                input_hash=f"session:{session_id}",
            )

        # Deserialize CLIP embedding from raw float32 bytes.
        clip_embedding = np.frombuffer(feature_vector, dtype=np.float32)
        if clip_embedding.shape[0] != _CLIP_DIM:
            # Malformed embedding — treat as no-face path to avoid crash.
            latency_ms = (time.perf_counter() - start) * 1000.0
            return ScoreResult(
                confidence=_NO_FACE_CONFIDENCE,
                verdict=classify(_NO_FACE_CONFIDENCE),
                top_features=[Feature(name="malformed_embedding", weight=1.0)],
                latency_ms=latency_ms,
                model_version=self.version,
                backend=self.backend,
                input_hash=f"session:{session_id}",
            )

        # Build (513,) feature vector: [face_detected_flag, *clip_embedding].
        face_flag = 1.0 if face_detected else 0.0
        feat = np.concatenate(([face_flag], clip_embedding.astype(np.float64)))

        # Model inference: P(deepfake).
        raw_confidence: float = float(self._clf.predict_proba([feat])[0][1])
        raw_confidence = clamp(raw_confidence)

        # Temporal smoothing: weighted blend of current frame and rolling mean.
        if session_id not in self._session_scores:
            self._session_scores[session_id] = deque(maxlen=_ROLLING_WINDOW)
        window = self._session_scores[session_id]

        if window:
            rolling_mean = float(np.mean(window))
            confidence = clamp(
                _CURRENT_WEIGHT * raw_confidence + _ROLLING_WEIGHT * rolling_mean
            )
        else:
            confidence = raw_confidence

        # Append the raw per-frame score (not the blended value) to the
        # window so the rolling mean tracks actual model output rather
        # than a recursively smoothed value.
        window.append(raw_confidence)

        # Compose top features for explainability.
        fired: list[Feature] = [
            Feature(name="clip_embedding_score", weight=round(raw_confidence, 4)),
            Feature(name="face_detected", weight=round(face_flag, 4)),
        ]
        if len(window) > 1:
            fired.append(
                Feature(
                    name="temporal_rolling_mean",
                    weight=round(float(np.mean(window)), 4),
                )
            )
        fired.sort(key=lambda f: f.weight, reverse=True)

        latency_ms = (time.perf_counter() - start) * 1000.0
        return ScoreResult(
            confidence=confidence,
            verdict=classify(confidence),
            top_features=fired[:3],
            latency_ms=latency_ms,
            model_version=self.version,
            backend=self.backend,
            input_hash=f"session:{session_id}",
        )

    # ── Unsupported RPCs ──────────────────────────────────────────────

    def score_prompt(self, text: str, context: str = "") -> ScoreResult:
        raise NotImplementedError("VideoModel does not score prompts.")

    def score_phishing(self, text: str, kind: str = "") -> ScoreResult:
        raise NotImplementedError("VideoModel does not score phishing.")

    def score_media(self, features: MediaFeatures) -> ScoreResult:
        raise NotImplementedError(
            "VideoModel does not score media files. "
            "Use MediaModel (VERTGUARD_ML_BACKEND=media)."
        )

    def score_identity(self, features: IdentityFeatures) -> ScoreResult:
        raise NotImplementedError(
            "VideoModel does not score identity claims. "
            "Use IdentityModel (VERTGUARD_ML_BACKEND=identity)."
        )
