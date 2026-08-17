package handlers

import (
	"context"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/ml"
)

// voiceCloneRiskThreshold is the confidence level at which voice_clone_risk
// is set true in the response. Matches the eval threshold in
// training/configs/voice_clone.yaml.
const voiceCloneRiskThreshold = 0.55

// AudioMLEnricher is the narrow ML interface the audio handler depends on.
// *ml.AudioEnricher satisfies it. Nil = scoring unavailable (returns 503).
type AudioMLEnricher interface {
	ScoreAudio(ctx context.Context, sessionID string, mfccHash, spectralHash []byte, durationMs float32, voiceDetected bool, correlationID, tenant string) (*ml.Result, error)
}

// AudioHandler serves POST /api/v1/audio/score.
type AudioHandler struct {
	ML     AudioMLEnricher
	Logger zerolog.Logger
	Tenant string
}

// NewAudioHandler returns an AudioHandler wired to the given ML enricher.
func NewAudioHandler(ml AudioMLEnricher, logger zerolog.Logger) *AudioHandler {
	return &AudioHandler{
		ML:     ml,
		Logger: logger.With().Str("handler", "audio").Logger(),
	}
}

// WithTenant tags emitted events. Returns h for chaining.
func (h *AudioHandler) WithTenant(tenant string) *AudioHandler {
	h.Tenant = tenant
	return h
}

// audioScoreRequest is the JSON body accepted by Score.
type audioScoreRequest struct {
	SessionID     string  `json:"session_id"`
	MfccHash      string  `json:"mfcc_hash"`     // hex-encoded 32-byte SHA-256
	SpectralHash  string  `json:"spectral_hash"` // hex-encoded 32-byte SHA-256
	DurationMs    float32 `json:"duration_ms"`
	VoiceDetected bool    `json:"voice_detected"`
}

// audioScoreResponse is the JSON envelope returned by Score.
type audioScoreResponse struct {
	ScanID         string  `json:"scan_id"`
	Verdict        string  `json:"verdict"`
	Confidence     float64 `json:"confidence"`
	VoiceCloneRisk bool    `json:"voice_clone_risk"`
	ModelVersion   string  `json:"model_version"`
	LatencyMs      float64 `json:"latency_ms,omitempty"`
}

// Score handles POST /api/v1/audio/score.
func (h *AudioHandler) Score(w http.ResponseWriter, r *http.Request) {
	if h.ML == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "ml_unavailable",
			"audio ML enricher not configured — deploy voice-clone weights and set VERTGUARD_ML_AUDIO_MODEL_DIR")
		return
	}

	var req audioScoreRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "session_id_missing", "session_id is required")
		return
	}
	if req.MfccHash == "" {
		writeJSONError(w, http.StatusBadRequest, "mfcc_hash_missing", "mfcc_hash is required")
		return
	}
	if req.SpectralHash == "" {
		writeJSONError(w, http.StatusBadRequest, "spectral_hash_missing", "spectral_hash is required")
		return
	}

	mfccBytes, err := hex.DecodeString(req.MfccHash)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "mfcc_hash_invalid", "mfcc_hash must be a valid hex string")
		return
	}
	spectralBytes, err := hex.DecodeString(req.SpectralHash)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "spectral_hash_invalid", "spectral_hash must be a valid hex string")
		return
	}

	scanID := uuid.NewString()
	start := time.Now()

	result, err := h.ML.ScoreAudio(
		r.Context(),
		req.SessionID,
		mfccBytes,
		spectralBytes,
		req.DurationMs,
		req.VoiceDetected,
		scanID,
		h.Tenant,
	)
	if err != nil {
		h.Logger.Debug().Err(err).Str("scan_id", scanID).Msg("audio ml score failed")
		writeJSONError(w, http.StatusServiceUnavailable, "ml_unavailable",
			"audio ML service unavailable — try again later")
		return
	}

	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0

	resp := audioScoreResponse{
		ScanID:         scanID,
		Verdict:        result.Verdict,
		Confidence:     result.Confidence,
		VoiceCloneRisk: result.Confidence >= voiceCloneRiskThreshold,
		ModelVersion:   result.ModelVersion,
		LatencyMs:      latencyMs,
	}

	h.Logger.Info().
		Str("scan_id", scanID).
		Str("session_id", req.SessionID).
		Str("verdict", resp.Verdict).
		Float64("confidence", resp.Confidence).
		Bool("voice_clone_risk", resp.VoiceCloneRisk).
		Str("model_version", resp.ModelVersion).
		Float64("latency_ms", latencyMs).
		Msg("audio_score")

	writeJSON(w, http.StatusOK, resp)
}
