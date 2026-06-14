"""Model interface shared by every backend.

The contract is intentionally tight: backends produce a confidence in
[0,1], a verdict string matching the Go scanner enum, an ordered list
of contributing features (optional), and self-report their version +
backend tag for log-time auditability.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

# Verdict thresholds match internal/prompt/scorer.go defaults so the
# Python stub yields the same classification the Go side would for
# matching numerical scores. Operators tune the Go side; the Python
# side reports the verdict it computed for transparency only — the Go
# scanner re-applies its own thresholds when folding.
VERDICT_CLEAN = "CLEAN"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_BLOCKED = "BLOCKED"

DEFAULT_CLEAN_T = 0.3
DEFAULT_BLOCK_T = 0.7


@dataclass(frozen=True)
class Feature:
    name: str
    weight: float


@dataclass(frozen=True)
class ScoreResult:
    confidence: float
    verdict: str
    top_features: list[Feature] = field(default_factory=list)
    latency_ms: float = 0.0
    model_version: str = "unknown"
    backend: str = "unknown"
    input_hash: str = ""


def hash_input(text: str) -> str:
    """SHA-256 of the raw input, hex-encoded with the sha256: prefix.

    Matches the Go scanner's InputHash format so the two sides emit the
    same value for the same bytes.
    """
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def classify(score: float, clean_t: float = DEFAULT_CLEAN_T, block_t: float = DEFAULT_BLOCK_T) -> str:
    if score >= block_t:
        return VERDICT_BLOCKED
    if score >= clean_t:
        return VERDICT_SUSPICIOUS
    return VERDICT_CLEAN


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


@dataclass(frozen=True)
class MediaFeatures:
    """Extracted media metadata sent to ML — no raw bytes."""
    file_hash: str
    mime_type: str
    file_size: int
    has_c2pa_manifest: bool
    c2pa_signature_valid: bool


@dataclass(frozen=True)
class IdentityFeatures:
    """Derived identity signals — no raw PII."""
    claim_type: str          # "passport" | "national_id" | "driver_license" | "login_credentials"
    context: str             # "kyc" | "login" | "account_recovery"
    name_token_count: int
    email_domain_is_disposable: bool
    id_format_valid: bool
    issuer_country: str      # ISO-3166-1 alpha-2, uppercase
    has_dob: bool
    replay_count: int


class Model(ABC):
    """Abstract backend.

    Subclasses implement score_prompt / score_phishing. Both share the
    ScoreResult shape because the gRPC contract returns the same
    ScoreResponse for both RPCs.
    """

    name: str = "unknown"
    version: str = "unknown"
    backend: str = "unknown"
    training_summary: str = ""
    eval_metrics_json: str = "{}"

    @abstractmethod
    def score_prompt(self, text: str, context: str = "") -> ScoreResult: ...

    @abstractmethod
    def score_phishing(self, text: str, kind: str = "") -> ScoreResult: ...

    @abstractmethod
    def score_media(self, features: MediaFeatures) -> ScoreResult: ...

    @abstractmethod
    def score_identity(self, features: IdentityFeatures) -> ScoreResult: ...
