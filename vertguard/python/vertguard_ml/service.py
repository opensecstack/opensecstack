"""gRPC service implementation.

Wraps a Model instance and translates between the protobuf shapes and
the dataclass-shaped ScoreResult. Every RPC is logged with a stable
event name + correlation id (when supplied by the caller) so log
stitching with the Go scanner works.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

import grpc
import structlog

from vertguard_ml.models.base import IdentityFeatures, MediaFeatures, Model, ScoreResult
from vertguard_ml.models.stub import StubModel

if TYPE_CHECKING:
    from vertguard_ml.proto.ml.v1 import inference_pb2, inference_pb2_grpc
else:
    # Generated stubs are imported lazily so the package is importable
    # in environments where protoc has not yet been run (e.g. CI lint
    # stage). Tests that exercise the gRPC surface fail-fast if the
    # stubs are missing.
    try:
        from vertguard_ml.proto.ml.v1 import inference_pb2, inference_pb2_grpc
    except ImportError:  # pragma: no cover
        inference_pb2 = None  # type: ignore[assignment]
        inference_pb2_grpc = None  # type: ignore[assignment]


log = structlog.get_logger(__name__)


def _result_to_proto(result: ScoreResult) -> Any:
    """Convert a ScoreResult dataclass to the proto ScoreResponse."""
    response = inference_pb2.ScoreResponse(
        confidence=result.confidence,
        verdict=result.verdict,
        latency_ms=result.latency_ms,
        model_version=result.model_version,
        input_hash=result.input_hash,
    )
    for feat in result.top_features:
        fw = response.top_features.add()
        fw.name = feat.name
        fw.weight = feat.weight
    return response


def select_backend() -> Model:
    """Pick a backend based on VERTGUARD_ML_BACKEND. Default: stub."""
    backend = os.environ.get("VERTGUARD_ML_BACKEND", "stub").lower()
    if backend == "stub":
        return StubModel()
    if backend == "distilbert":
        # WHY: keep the import local — the [ml] extra is not always
        # installed and we don't want server import to break for stub
        # operators when transformers is missing.
        from vertguard_ml.models.distilbert import DistilBertModel

        return DistilBertModel()
    if backend == "media":
        from vertguard_ml.models.media import MediaModel
        return MediaModel()
    if backend == "identity":
        from vertguard_ml.models.identity import IdentityModel
        return IdentityModel()
    if backend == "video":
        from vertguard_ml.models.video import VideoModel
        return VideoModel()
    if backend == "audio":
        from vertguard_ml.models.audio import AudioModel
        return AudioModel()
    raise ValueError(f"unknown VERTGUARD_ML_BACKEND: {backend!r}")


def _try_load_audio_model() -> "AudioModel | None":
    """Attempt to load the AudioModel; return None on any error.

    Called at service construction time so ScoreAudio has real weights
    when they are deployed, and silently falls back to the stub when
    they are not (soft-fail — audio detection is optional).
    """
    try:
        from vertguard_ml.models.audio import AudioModel
        model = AudioModel()
        log.info("audio_model_loaded", version=model.version)
        return model
    except Exception as exc:  # noqa: BLE001
        log.info(
            "audio_model_unavailable",
            reason=str(exc),
            fallback="stub",
        )
        return None


def _try_load_video_model() -> "VideoModel | None":
    """Attempt to load the VideoModel; return None on any error.

    Called at service construction time so ScoreVideoStream has a real
    model when weights are deployed, and silently falls back to the
    stub when they are not (soft-fail — video detection is optional).
    """
    try:
        from vertguard_ml.models.video import VideoModel
        model = VideoModel()
        log.info("video_model_loaded", version=model.version)
        return model
    except Exception as exc:  # noqa: BLE001
        log.info(
            "video_model_unavailable",
            reason=str(exc),
            fallback="stub",
        )
        return None


class InferenceService:
    """Concrete gRPC servicer.

    Construction is decoupled from the generated Servicer base class so
    tests can swap the model without touching the wire format. The
    add_to_server helper does the binding.
    """

    def __init__(self, model: Model | None = None) -> None:
        self.model = model or select_backend()
        log.info("model_loaded", backend=self.model.backend, version=self.model.version)
        # Phase 4.3 — AudioModel is loaded alongside the primary model so
        # ScoreAudio has real weights when available. Soft-fail: if the
        # audio weights are not deployed the stub path is used instead.
        self._audio_model = _try_load_audio_model()
        # Phase 4.3 — VideoModel is loaded alongside the primary model so
        # ScoreVideoStream has real weights when available. Soft-fail: if
        # the video weights are not deployed the stub path is used instead.
        self._video_model = _try_load_video_model()

    # --- RPCs ------------------------------------------------------------

    def ScorePrompt(self, request: Any, context: grpc.ServicerContext) -> Any:
        if not request.input:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "input must not be empty")
        try:
            result = self.model.score_prompt(request.input, request.context or "")
        except Exception as e:  # noqa: BLE001
            log.error("score_prompt_failed", error=str(e))
            context.abort(grpc.StatusCode.INTERNAL, f"score_prompt failed: {e}")
        log.info(
            "score_prompt",
            verdict=result.verdict,
            confidence=round(result.confidence, 4),
            latency_ms=round(result.latency_ms, 3),
            model_version=result.model_version,
            correlation_id=request.correlation_id,
        )
        return _result_to_proto(result)

    def ScorePhishing(self, request: Any, context: grpc.ServicerContext) -> Any:
        if not request.input:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "input must not be empty")
        try:
            result = self.model.score_phishing(request.input, request.kind or "")
        except Exception as e:  # noqa: BLE001
            log.error("score_phishing_failed", error=str(e))
            context.abort(grpc.StatusCode.INTERNAL, f"score_phishing failed: {e}")
        log.info(
            "score_phishing",
            verdict=result.verdict,
            confidence=round(result.confidence, 4),
            latency_ms=round(result.latency_ms, 3),
            kind=request.kind,
            correlation_id=request.correlation_id,
        )
        return _result_to_proto(result)

    def ScoreMedia(self, request: Any, context: grpc.ServicerContext) -> Any:
        if not request.file_hash:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "file_hash must not be empty")
        try:
            from vertguard_ml.models.base import MediaFeatures
            features = MediaFeatures(
                file_hash=request.file_hash,
                mime_type=request.mime_type or "",
                file_size=request.file_size,
                has_c2pa_manifest=request.has_c2pa_manifest,
                c2pa_signature_valid=request.c2pa_signature_valid,
            )
            result = self.model.score_media(features)
        except NotImplementedError as e:
            context.abort(grpc.StatusCode.UNIMPLEMENTED, str(e))
        except Exception as e:  # noqa: BLE001
            log.error("score_media_failed", error=str(e))
            context.abort(grpc.StatusCode.INTERNAL, f"score_media failed: {e}")
        log.info(
            "score_media",
            verdict=result.verdict,
            confidence=round(result.confidence, 4),
            latency_ms=round(result.latency_ms, 3),
            file_hash=request.file_hash[:16] + "...",
            correlation_id=request.correlation_id,
        )
        return _result_to_proto(result)

    def ScoreIdentity(self, request: Any, context: grpc.ServicerContext) -> Any:
        if not request.claim_type:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "claim_type must not be empty")
        try:
            features = IdentityFeatures(
                claim_type=request.claim_type,
                context=request.context or "kyc",
                name_token_count=request.name_token_count,
                email_domain_is_disposable=request.email_domain_is_disposable,
                id_format_valid=request.id_format_valid,
                issuer_country=request.issuer_country or "",
                has_dob=request.has_dob,
                replay_count=request.replay_count,
            )
            result = self.model.score_identity(features)
        except NotImplementedError as e:
            context.abort(grpc.StatusCode.UNIMPLEMENTED, str(e))
        except Exception as e:  # noqa: BLE001
            log.error("score_identity_failed", error=str(e))
            context.abort(grpc.StatusCode.INTERNAL, f"score_identity failed: {e}")
        log.info(
            "score_identity",
            verdict=result.verdict,
            confidence=round(result.confidence, 4),
            latency_ms=round(result.latency_ms, 3),
            claim_type=request.claim_type,
            correlation_id=request.correlation_id,
        )
        return _result_to_proto(result)

    def ScoreAudio(self, request: Any, context: grpc.ServicerContext) -> Any:
        if not request.session_id:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "session_id must not be empty")
        # Use the dedicated AudioModel when weights are deployed; fall back
        # to StubModel.score_audio so the endpoint is always usable.
        audio_model = self._audio_model
        try:
            if audio_model is not None:
                result = audio_model.score_audio(
                    mfcc_hash=bytes(request.mfcc_hash),
                    spectral_hash=bytes(request.spectral_hash),
                    duration_ms=request.duration_ms,
                    voice_detected=request.voice_detected,
                )
            else:
                result = self.model.score_audio(
                    mfcc_hash=bytes(request.mfcc_hash),
                    spectral_hash=bytes(request.spectral_hash),
                    duration_ms=request.duration_ms,
                    voice_detected=request.voice_detected,
                )
        except NotImplementedError as e:
            context.abort(grpc.StatusCode.UNIMPLEMENTED, str(e))
        except Exception as e:  # noqa: BLE001
            log.error("score_audio_failed", error=str(e))
            context.abort(grpc.StatusCode.INTERNAL, f"score_audio failed: {e}")
        log.info(
            "score_audio",
            verdict=result.verdict,
            confidence=round(result.confidence, 4),
            latency_ms=round(result.latency_ms, 3),
            session_id=request.session_id,
            voice_detected=request.voice_detected,
            correlation_id=request.correlation_id,
        )
        return _result_to_proto(result)

    def ScoreVideoStream(self, request_iterator: Any, context: grpc.ServicerContext) -> Any:
        # Phase 4.3 — real video deepfake scoring via VideoModel.
        # Each VideoFrameRequest carries a 512-dim CLIP embedding (raw
        # float32 bytes) and a face_detected flag. The VideoModel scores
        # each frame and applies session-level temporal smoothing to
        # reduce single-frame false positives.
        #
        # Soft-fail: if VideoModel weights are not deployed, _video_model
        # is None and we fall back to the stub path (CLEAN, 0.0 confidence)
        # so the Go streaming plumbing can be exercised without real weights.
        import time as _time

        # Determine which model to use for this stream.
        video_model = self._video_model  # may be None

        for req in request_iterator:
            log.debug(
                "score_video_frame",
                session_id=req.session_id,
                frame_seq=req.frame_seq,
                face_detected=req.face_detected,
            )

            if video_model is not None:
                try:
                    result = video_model.score_frame(
                        feature_vector=req.feature_vector,
                        face_detected=req.face_detected,
                        session_id=req.session_id,
                    )
                    confidence = result.confidence
                    verdict = result.verdict
                    latency_ms = result.latency_ms
                    model_version = result.model_version
                except Exception as exc:  # noqa: BLE001
                    # Soft-fail individual frame errors so a transient
                    # deserialization issue doesn't kill the stream.
                    log.warning(
                        "score_video_frame_failed",
                        session_id=req.session_id,
                        frame_seq=req.frame_seq,
                        error=str(exc),
                    )
                    start = _time.perf_counter()
                    confidence = 0.0
                    verdict = "CLEAN"
                    latency_ms = (_time.perf_counter() - start) * 1000.0
                    model_version = self.model.version
            else:
                # Stub fallback — no weights deployed.
                start = _time.perf_counter()
                confidence = 0.0
                verdict = "CLEAN"
                latency_ms = (_time.perf_counter() - start) * 1000.0
                model_version = self.model.version

            log.info(
                "score_video_frame_done",
                session_id=req.session_id,
                frame_seq=req.frame_seq,
                verdict=verdict,
                confidence=round(confidence, 4),
                latency_ms=round(latency_ms, 3),
                model_version=model_version,
            )
            yield inference_pb2.VideoScoreEvent(
                session_id=req.session_id,
                frame_seq=req.frame_seq,
                confidence=confidence,
                verdict=verdict,
                latency_ms=latency_ms,
                model_version=model_version,
            )

    def BatchScorePrompt(
        self, request_iterator: Iterator[Any], context: grpc.ServicerContext
    ) -> Iterator[Any]:
        # WHY: bidirectional stream lets the eval harness pipeline
        # requests without TCP round-trip overhead per sample.
        for req in request_iterator:
            if not req.input:
                # Skip empty inputs rather than aborting the whole stream;
                # the eval harness sends batched corpora and one bad
                # sample shouldn't sink the run.
                log.warning("batch_skip_empty_input", correlation_id=req.correlation_id)
                continue
            result = self.model.score_prompt(req.input, req.context or "")
            log.info(
                "batch_score_prompt",
                verdict=result.verdict,
                confidence=round(result.confidence, 4),
                correlation_id=req.correlation_id,
            )
            yield _result_to_proto(result)

    def ModelInfo(self, request: Any, context: grpc.ServicerContext) -> Any:
        import time

        return inference_pb2.ModelInfoResponse(
            name=self.model.name,
            version=self.model.version,
            training_summary=self.model.training_summary,
            loaded_at=int(time.time()),
            backend=self.model.backend,
            eval_metrics_json=self.model.eval_metrics_json,
        )


def add_to_server(servicer: InferenceService, server: grpc.Server) -> None:
    """Bind the servicer to a gRPC server using the generated registration helper."""
    if inference_pb2_grpc is None:  # pragma: no cover
        raise RuntimeError(
            "Generated proto stubs not found. Run scripts/gen_proto.sh first."
        )
    inference_pb2_grpc.add_InferenceServiceServicer_to_server(servicer, server)
