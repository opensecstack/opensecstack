"""Deterministic heuristic model.

Phase 4.2 default. Exists so the Go side can prove gRPC wiring before
real weights are trained. Triggers and weights mirror the canonical
prompt-injection vocabulary and the regex prefilter in
internal/prompt and internal/phishing.
"""

from __future__ import annotations

import re
import time

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

# Trigger weights tuned so a single high-signal phrase hits SUSPICIOUS
# and any two compounding phrases hit BLOCKED, matching the Go corpus
# expectations.
PROMPT_TRIGGERS: dict[str, float] = {
    "ignore previous": 0.45,
    "ignore all": 0.40,
    "system prompt": 0.40,
    "dan": 0.50,
    "jailbreak": 0.40,
    "no restrictions": 0.50,
    "developer mode": 0.40,
    "you are now": 0.30,
    "disregard": 0.30,
    "reveal your": 0.35,
    "forget everything": 0.40,
    "act as": 0.20,
}

# Phishing-specific phrase triggers. URL / brand-host heuristics live
# below in dedicated checks because they need pattern matching, not
# substring tests.
PHISHING_TRIGGERS: dict[str, float] = {
    "verify your account": 0.40,
    "click here": 0.30,
    "urgent": 0.20,
    "suspended": 0.30,
    "confirm your password": 0.45,
    "enable macros": 0.40,
    "social security number": 0.50,
    "immediate action": 0.35,
}

CONTEXT_MOD: dict[str, float] = {
    "internal_dev_tool": -0.20,
    "authenticated_operator": -0.10,
    "user_chat_input": 0.0,
    "default": 0.0,
    "untrusted_third_party": 0.10,
    "untrusted_document_content": 0.20,
}

# Brand tokens used to detect host-mismatch (e.g. login.microsoft.com.evil.tld).
KNOWN_BRANDS = (
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "facebook",
    "netflix",
    "chase",
    "wellsfargo",
    "bankofamerica",
)

URL_RE = re.compile(r"https?://([^\s/]+)", re.IGNORECASE)
USERINFO_AT_RE = re.compile(r"https?://[^\s/]*@[^\s/]+", re.IGNORECASE)


def _phishing_url_features(text: str) -> list[Feature]:
    """Pull URL-shape indicators that aren't simple substring triggers."""
    features: list[Feature] = []

    if USERINFO_AT_RE.search(text):
        features.append(Feature(name="url_userinfo_at", weight=0.50))

    for host in URL_RE.findall(text):
        host_l = host.lower()
        # Brand-host mismatch: brand appears as a non-final label, the
        # rightmost label is something else (e.g. evil.tld).
        labels = host_l.split(".")
        if len(labels) >= 3:
            tail = ".".join(labels[-2:])
            for brand in KNOWN_BRANDS:
                if brand in host_l and brand not in tail:
                    features.append(Feature(name=f"brand_host_mismatch:{brand}", weight=0.50))
                    break

    return features


class StubModel(Model):
    name = "vertguard-stub"
    version = "stub-v1"
    backend = "stub"
    training_summary = (
        "Heuristic stub. No training data. Trigger vocabulary matches the Go "
        "regex prefilter; verdicts are coherent but recall/precision are not "
        "production-grade."
    )
    eval_metrics_json = '{"note":"stub model — eval not applicable"}'

    def _score(
        self,
        text: str,
        triggers: dict[str, float],
        extra_features: list[Feature] | None = None,
        context: str = "",
    ) -> ScoreResult:
        start = time.perf_counter()

        lowered = text.lower()
        score = 0.0
        fired: list[Feature] = []

        for trigger, weight in triggers.items():
            if trigger in lowered:
                score = clamp(score + weight)
                fired.append(Feature(name=trigger, weight=weight))

        if extra_features:
            for feat in extra_features:
                score = clamp(score + feat.weight)
                fired.append(feat)

        score = clamp(score + CONTEXT_MOD.get(context, 0.0))

        # WHY: top-3 by weight desc — empty list when nothing fired so
        # the Go side sees an empty FeatureWeight list (= no
        # explainability) rather than a noisy zero-weight entry.
        fired.sort(key=lambda f: f.weight, reverse=True)
        top = fired[:3]

        verdict = classify(score)
        latency_ms = (time.perf_counter() - start) * 1000.0

        return ScoreResult(
            confidence=score,
            verdict=verdict,
            top_features=top,
            latency_ms=latency_ms,
            model_version=self.version,
            backend=self.backend,
            input_hash=hash_input(text),
        )

    def score_prompt(self, text: str, context: str = "") -> ScoreResult:
        return self._score(text, PROMPT_TRIGGERS, extra_features=None, context=context)

    def score_phishing(self, text: str, kind: str = "") -> ScoreResult:
        # Kind hints which feature family carries weight, but stub
        # treats all kinds uniformly: the URL features only fire if
        # there's actually a URL in the text, so passing kind="email"
        # with embedded URLs still surfaces them.
        url_feats = _phishing_url_features(text)
        return self._score(text, PHISHING_TRIGGERS, extra_features=url_feats, context="")

    def score_media(self, features: MediaFeatures) -> ScoreResult:
        import time
        start = time.perf_counter()
        score = 0.0
        fired: list[Feature] = []
        # No C2PA manifest is a moderate signal.
        if not features.has_c2pa_manifest:
            score = clamp(score + 0.25)
            fired.append(Feature(name="no_c2pa_manifest", weight=0.25))
        # C2PA present but invalid is a stronger signal.
        elif not features.c2pa_signature_valid:
            score = clamp(score + 0.50)
            fired.append(Feature(name="c2pa_invalid_signature", weight=0.50))
        # Large video files without manifest warrant slight elevation.
        if features.file_size > 10 * 1024 * 1024 and not features.has_c2pa_manifest:
            score = clamp(score + 0.10)
            fired.append(Feature(name="large_file_no_manifest", weight=0.10))
        fired.sort(key=lambda f: f.weight, reverse=True)
        verdict = classify(score)
        latency_ms = (time.perf_counter() - start) * 1000.0
        return ScoreResult(
            confidence=score,
            verdict=verdict,
            top_features=fired[:3],
            latency_ms=latency_ms,
            model_version=self.version,
            backend=self.backend,
            input_hash=features.file_hash,
        )

    def score_audio(
        self,
        mfcc_hash: bytes,
        spectral_hash: bytes,
        duration_ms: float,
        voice_detected: bool,
    ) -> ScoreResult:
        import time
        start = time.perf_counter()

        if not voice_detected:
            latency_ms = (time.perf_counter() - start) * 1000.0
            return ScoreResult(
                confidence=0.02,
                verdict=classify(0.02),
                top_features=[],
                latency_ms=latency_ms,
                model_version=self.version,
                backend=self.backend,
                input_hash=hash_input(
                    f"mfcc:{mfcc_hash[:2].hex()}:spectral:{spectral_hash[:2].hex()}"
                ),
            )

        # Derive a [0, 1] base confidence from the first 2 bytes of mfcc_hash.
        # This gives a deterministic, reproducible heuristic that varies across
        # different fingerprints while remaining independent of real ML weights.
        base = int.from_bytes(mfcc_hash[:2], "big") / 0xFFFF
        score = clamp(base)

        fired: list[Feature] = []
        if score > 0.0:
            fired.append(Feature(name="mfcc_hash_heuristic", weight=score))

        fired.sort(key=lambda f: f.weight, reverse=True)
        verdict = classify(score)
        latency_ms = (time.perf_counter() - start) * 1000.0
        return ScoreResult(
            confidence=score,
            verdict=verdict,
            top_features=fired[:3],
            latency_ms=latency_ms,
            model_version=self.version,
            backend=self.backend,
            input_hash=hash_input(
                f"mfcc:{mfcc_hash[:2].hex()}:spectral:{spectral_hash[:2].hex()}"
            ),
        )

    def score_identity(self, features: IdentityFeatures) -> ScoreResult:
        import time
        start = time.perf_counter()
        score = 0.0
        fired: list[Feature] = []

        # Sanctioned jurisdiction is a strong signal.
        SANCTIONED = {"KP", "IR", "SY", "CU", "BY"}
        if features.issuer_country.upper() in SANCTIONED:
            score = clamp(score + 0.55)
            fired.append(Feature(name="sanctioned_jurisdiction", weight=0.55))

        # Disposable email moderate signal.
        if features.email_domain_is_disposable:
            score = clamp(score + 0.35)
            fired.append(Feature(name="disposable_email", weight=0.35))

        # Invalid ID format moderate signal.
        if not features.id_format_valid and features.issuer_country:
            score = clamp(score + 0.30)
            fired.append(Feature(name="id_format_invalid", weight=0.30))

        # Replay: escalates with count.
        if features.replay_count >= 5:
            w = min(0.10 * features.replay_count, 0.40)
            score = clamp(score + w)
            fired.append(Feature(name=f"replay_count_{features.replay_count}", weight=w))

        # Missing DOB on KYC claim is a weak signal.
        if not features.has_dob and features.claim_type in ("passport", "national_id"):
            score = clamp(score + 0.10)
            fired.append(Feature(name="missing_dob_kyc", weight=0.10))

        # Context modifier: account_recovery is higher risk.
        if features.context == "account_recovery":
            score = clamp(score + 0.05)
        elif features.context == "login":
            score = clamp(score - 0.05)

        fired.sort(key=lambda f: f.weight, reverse=True)
        verdict = classify(score)
        latency_ms = (time.perf_counter() - start) * 1000.0
        return ScoreResult(
            confidence=score,
            verdict=verdict,
            top_features=fired[:3],
            latency_ms=latency_ms,
            model_version=self.version,
            backend=self.backend,
            input_hash=hash_input(f"{features.claim_type}:{features.issuer_country}:{features.replay_count}"),
        )
