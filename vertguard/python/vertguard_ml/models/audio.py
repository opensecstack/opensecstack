"""Voice clone detection backend.

Phase 4.3 — Gradient Boosting classifier on a four-element feature vector
derived from MFCC and spectral fingerprints produced by the Go-side
audio-fingerprint crate. Requires trained weights at
VERTGUARD_ML_AUDIO_MODEL_DIR (default
/var/lib/vertguard/models/voice-clone). Until weights are deployed,
instantiation raises FileNotFoundError.

Detection approach (Phase 4.3):
  A sklearn GradientBoostingClassifier is trained on ASVspoof2019 and
  VCTK synthesis corpora (see training/configs/voice_clone.yaml). The
  input feature vector is intentionally compact (4 floats) so the
  classifier runs on CPU in <1 ms without GPU resources.

  Early-return rule: when voice_detected=False (no voice activity
  detected by the Go VAD pre-step) the model returns CLEAN at 0.03
  without running inference — the classifier is calibrated only on
  frames that contain speech.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from vertguard_ml.models.base import (
    Feature,
    IdentityFeatures,
    MediaFeatures,
    Model,
    ScoreResult,
    classify,
    clamp,
    hash_input,
)

DEFAULT_AUDIO_MODEL_DIR = "/var/lib/vertguard/models/voice-clone"

# Confidence returned when no voice activity is detected — below the
# CLEAN threshold (0.3) so it never triggers escalation.
_NO_VOICE_CONFIDENCE = 0.03


class AudioModel(Model):
    name = "vertguard-voice-clone"
    backend = "sklearn-cpu"
    training_summary = (
        "Gradient Boosting classifier trained on ASVspoof2019 and VCTK "
        "synthesis corpora. Input: 4-element feature vector derived from "
        "MFCC hash and spectral fingerprint — no raw audio bytes. "
        "See training/configs/voice_clone.yaml and model_card.yaml."
    )

    def __init__(self, weights_path: str | None = None) -> None:
        try:
            import joblib
        except ImportError as e:  # pragma: no cover
            raise NotImplementedError(
                "AudioModel requires scikit-learn and joblib: "
                "pip install vertguard-ml[training]"
            ) from e

        audio_dir = weights_path or os.environ.get(
            "VERTGUARD_ML_AUDIO_MODEL_DIR", DEFAULT_AUDIO_MODEL_DIR
        )
        model_path = Path(audio_dir) / "model.joblib"

        if not Path(audio_dir).exists():
            raise FileNotFoundError(
                f"Audio ML model directory not found: {audio_dir}. "
                "Train via `python -m training.train --config "
                "training/configs/voice_clone.yaml` or set "
                "VERTGUARD_ML_AUDIO_MODEL_DIR."
            )
        if not model_path.exists():
            raise FileNotFoundError(
                f"Audio ML model file not found: {model_path}. "
                "Train via `python -m training.train --config "
                "training/configs/voice_clone.yaml`."
            )

        self._clf = joblib.load(str(model_path))
        self.version = self._read_version(audio_dir)
        self.eval_metrics_json = self._read_eval_metrics(audio_dir)

    @staticmethod
    def _read_version(directory: str) -> str:
        card = Path(directory) / "model_card.yaml"
        if not card.exists():
            return "v0-uncarded"
        try:
            import yaml

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
            import json as _json
            import yaml

            with open(card, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            return _json.dumps(doc.get("eval", {}), separators=(",", ":"))
        except Exception:
            return "{}"

    def _build_feature_vector(
        self,
        mfcc_hash: bytes,
        spectral_hash: bytes,
        duration_ms: float,
        voice_detected: bool,
    ) -> list[float]:
        """Return the four-element numeric vector fed to the classifier.

        Features:
          [0] voice_detected  — 0.0 / 1.0 (boolean cast)
          [1] duration_sec    — chunk length in seconds (duration_ms / 1000)
          [2] mfcc_hash_norm  — first 4 bytes of mfcc_hash interpreted as a
                                big-endian uint32, normalised to [0, 1]
          [3] spectral_hash_norm — same normalisation on spectral_hash[:4]
        """
        voice_flag = 1.0 if voice_detected else 0.0
        duration_sec = duration_ms / 1000.0
        mfcc_norm = int.from_bytes(mfcc_hash[:4], "big") / (2**32)
        spectral_norm = int.from_bytes(spectral_hash[:4], "big") / (2**32)
        return [voice_flag, duration_sec, mfcc_norm, spectral_norm]

    def score_audio(
        self,
        mfcc_hash: bytes,
        spectral_hash: bytes,
        duration_ms: float,
        voice_detected: bool,
    ) -> ScoreResult:
        """Score an audio fingerprint for voice clone likelihood.

        Returns CLEAN at 0.03 immediately when voice_detected is False
        (no speech in chunk — classifier output would be meaningless).
        """
        start = time.perf_counter()

        if not voice_detected:
            latency_ms = (time.perf_counter() - start) * 1000.0
            return ScoreResult(
                confidence=_NO_VOICE_CONFIDENCE,
                verdict=classify(_NO_VOICE_CONFIDENCE),
                top_features=[],
                latency_ms=latency_ms,
                model_version=self.version,
                backend=self.backend,
                input_hash=hash_input(
                    f"mfcc:{mfcc_hash[:4].hex()}:spectral:{spectral_hash[:4].hex()}"
                ),
            )

        feat_vec = self._build_feature_vector(mfcc_hash, spectral_hash, duration_ms, voice_detected)

        # predict_proba returns [[p_clean, p_clone]]; we want p_clone.
        proba = self._clf.predict_proba([feat_vec])[0]
        confidence = clamp(float(proba[1]))

        fired: list[Feature] = []
        voice_flag, duration_sec, mfcc_norm, spectral_norm = feat_vec
        if mfcc_norm > 0.0:
            fired.append(Feature(name="mfcc_hash_norm", weight=mfcc_norm))
        if spectral_norm > 0.0:
            fired.append(Feature(name="spectral_hash_norm", weight=spectral_norm))
        if duration_sec > 0.0:
            fired.append(Feature(name="duration_sec", weight=min(duration_sec / 10.0, 1.0)))
        fired.sort(key=lambda f: f.weight, reverse=True)

        latency_ms = (time.perf_counter() - start) * 1000.0
        return ScoreResult(
            confidence=confidence,
            verdict=classify(confidence),
            top_features=fired[:3],
            latency_ms=latency_ms,
            model_version=self.version,
            backend=self.backend,
            input_hash=hash_input(
                f"mfcc:{mfcc_hash[:4].hex()}:spectral:{spectral_hash[:4].hex()}"
            ),
        )

    def score_prompt(self, text: str, context: str = "") -> ScoreResult:
        raise NotImplementedError("AudioModel does not score prompts.")

    def score_phishing(self, text: str, kind: str = "") -> ScoreResult:
        raise NotImplementedError("AudioModel does not score phishing.")

    def score_media(self, features: MediaFeatures) -> ScoreResult:
        raise NotImplementedError(
            "AudioModel does not score generic media. Use score_audio."
        )

    def score_identity(self, features: IdentityFeatures) -> ScoreResult:
        raise NotImplementedError(
            "AudioModel does not score identity claims. Use score_audio."
        )
