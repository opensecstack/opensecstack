"""Synthetic identity detection backend.

Phase 4.2 — Isolation Forest anomaly detector (unsupervised) on a
privacy-safe derived feature vector. Requires trained weights at
VERTGUARD_ML_IDENTITY_MODEL_DIR (default
/var/lib/vertguard/models/identity-gan). Until weights are deployed,
instantiation raises FileNotFoundError.

Detection approach (Phase 4.2):
  Isolation Forest scored on eight numeric signals derived from the Go
  scanner's IdentityFeatures envelope. No raw PII crosses the boundary;
  all signals are derived and normalised before the gRPC call is made.

  Override rules (hard-coded) are applied after the anomaly score is
  normalised so that high-confidence fraud signals are never masked by a
  low-anomaly forest score.
"""

from __future__ import annotations

import json
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

DEFAULT_IDENTITY_MODEL_DIR = "/var/lib/vertguard/models/identity-gan"

# Context-risk priors (account_recovery is structurally higher-risk than
# a routine KYC check; login sits in between).
_CONTEXT_RISK: dict[str, float] = {
    "account_recovery": 0.8,
    "login": 0.4,
    "kyc": 0.1,
}

# Claim-type priors (login_credentials carry the highest abuse surface;
# passports the lowest because the doc-auth pipeline catches forgeries
# separately).
_CLAIM_TYPE_RISK: dict[str, float] = {
    "login_credentials": 0.7,
    "driver_license": 0.3,
    "national_id": 0.2,
    "passport": 0.1,
}


class IdentityModel(Model):
    name = "vertguard-identity-gan"
    backend = "sklearn-cpu"
    training_summary = (
        "Isolation Forest anomaly detector trained on privacy-safe derived "
        "identity signals (no raw PII). Feature engineering and contamination "
        "rate tuned on synthetic fraud corpus. See model_card.yaml."
    )

    def __init__(self, weights_path: str | None = None) -> None:
        try:
            import joblib
        except ImportError as e:  # pragma: no cover
            raise NotImplementedError(
                "IdentityModel requires scikit-learn and joblib: "
                "pip install vertguard-ml[training]"
            ) from e

        identity_dir = weights_path or os.environ.get(
            "VERTGUARD_ML_IDENTITY_MODEL_DIR", DEFAULT_IDENTITY_MODEL_DIR
        )
        model_path = Path(identity_dir) / "model.joblib"
        risk_path = Path(identity_dir) / "country_risk_scores.json"

        if not Path(identity_dir).exists():
            raise FileNotFoundError(
                f"Identity ML model directory not found: {identity_dir}. "
                "Train via `python -m training.train --config "
                "training/configs/identity_gan.yaml` or set "
                "VERTGUARD_ML_IDENTITY_MODEL_DIR."
            )
        if not model_path.exists():
            raise FileNotFoundError(
                f"Identity ML model file not found: {model_path}. "
                "Train via `python -m training.train --config "
                "training/configs/identity_gan.yaml`."
            )
        if not risk_path.exists():
            raise FileNotFoundError(
                f"Country risk scores file not found: {risk_path}. "
                "Ensure country_risk_scores.json is present in "
                f"{identity_dir}."
            )

        self._clf = joblib.load(str(model_path))
        with open(risk_path, encoding="utf-8") as fh:
            self._country_risk: dict[str, float] = json.load(fh)

        self.version = self._read_version(identity_dir)
        self.eval_metrics_json = self._read_eval_metrics(identity_dir)

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
            import json as _json
            import yaml

            with open(card, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh) or {}
            return _json.dumps(doc.get("eval", {}), separators=(",", ":"))
        except Exception:
            return "{}"

    def _build_feature_vector(self, features: IdentityFeatures) -> list[float]:
        """Return the eight-element numeric vector fed to the Isolation Forest.

        All values are in [0, 1] so the forest treats each dimension with
        equal prior scale. Inversion of boolean signals aligns polarity so
        that higher always means higher risk (consistent with the confidence
        output direction).
        """
        disposable = float(features.email_domain_is_disposable)
        id_invalid = float(not features.id_format_valid)
        dob_missing = float(not features.has_dob)
        replay_norm = min(features.replay_count / 10.0, 1.0)
        name_norm = min(features.name_token_count / 5.0, 1.0)
        country_risk = self._country_risk.get(features.issuer_country.upper(), 0.5)
        context_risk = _CONTEXT_RISK.get(features.context, 0.4)
        claim_risk = _CLAIM_TYPE_RISK.get(features.claim_type, 0.3)
        return [
            disposable,
            id_invalid,
            dob_missing,
            replay_norm,
            name_norm,
            country_risk,
            context_risk,
            claim_risk,
        ]

    def score_identity(self, features: IdentityFeatures) -> ScoreResult:
        start = time.perf_counter()

        feat_vec = self._build_feature_vector(features)

        # Isolation Forest returns a negative anomaly score; more negative
        # means more anomalous. Normalise to [0, 1] confidence where 1 is
        # maximally suspicious.
        raw_score: float = float(self._clf.score_samples([feat_vec])[0])
        confidence = clamp(1.0 - (raw_score + 0.5))

        # Collect the signals that fired so callers have explainability.
        fired: list[Feature] = []
        (
            disposable,
            id_invalid,
            dob_missing,
            replay_norm,
            name_norm,
            country_risk,
            context_risk,
            claim_risk,
        ) = feat_vec

        if disposable:
            fired.append(Feature(name="disposable_email", weight=disposable))
        if id_invalid:
            fired.append(Feature(name="id_format_invalid", weight=id_invalid))
        if dob_missing:
            fired.append(Feature(name="dob_missing", weight=dob_missing))
        if replay_norm > 0.0:
            fired.append(Feature(name=f"replay_count_{features.replay_count}", weight=replay_norm))
        if country_risk > 0.0:
            fired.append(Feature(name=f"country_risk:{features.issuer_country.upper()}", weight=country_risk))
        if context_risk > 0.0:
            fired.append(Feature(name=f"context_risk:{features.context}", weight=context_risk))
        if claim_risk > 0.0:
            fired.append(Feature(name=f"claim_type_risk:{features.claim_type}", weight=claim_risk))

        # Hard override rules — floor confidence to prevent the anomaly
        # score from masking high-confidence fraud signals.
        if features.replay_count >= 3:
            confidence = max(confidence, 0.80)
            if not any(f.name.startswith("replay_count_") for f in fired):
                fired.append(
                    Feature(name=f"replay_count_{features.replay_count}", weight=replay_norm)
                )
        if features.email_domain_is_disposable and not features.id_format_valid:
            confidence = max(confidence, 0.70)

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
                f"{features.claim_type}:{features.issuer_country}:{features.replay_count}"
            ),
        )

    def score_prompt(self, text: str, context: str = "") -> ScoreResult:
        raise NotImplementedError("IdentityModel does not score prompts.")

    def score_phishing(self, text: str, kind: str = "") -> ScoreResult:
        raise NotImplementedError("IdentityModel does not score phishing.")

    def score_media(self, features: MediaFeatures) -> ScoreResult:
        raise NotImplementedError(
            "IdentityModel does not score generic media. Use score_identity."
        )
