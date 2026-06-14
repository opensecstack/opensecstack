package handlers

// VideoStreamHandler serves the Phase 4.3 WebRTC deepfake detection API.
//
// Routes:
//   POST /api/v1/video/session  — allocates a session_id (UUID)
//   WS   /api/v1/video/stream/{session_id} — bidirectional frame scoring stream
//
// The WebSocket stream accepts JSON frames from the client:
//
//	{"frame_seq": 1, "feature_vector": "<base64>", "face_detected": true}
//
// and replies per-frame:
//
//	{"frame_seq": 1, "confidence": 0.12, "verdict": "CLEAN", "latency_ms": 2.1}
//
// Soft-fail: when the ML service is unavailable, replies carry
// verdict "UNAVAILABLE" so the client can distinguish ML-down from
// a genuine CLEAN frame and degrade gracefully.
//
// No DB required: sessions are ephemeral. The Go side only tracks the
// session_id as a routing key; all temporal smoothing lives in the
// Python VideoModel.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/net/websocket"

	"github.com/opensecstack/vertguard/internal/ml"
	mlpb "github.com/opensecstack/vertguard/internal/ml/pb"
)

// VideoMLClient is the narrow interface VideoStreamHandler depends on.
// *ml.Client satisfies it; tests can inject a fake.
type VideoMLClient interface {
	ScoreVideoStream(ctx context.Context) (mlpb.InferenceService_ScoreVideoStreamClient, error)
}

// VideoStreamHandler provides the video session and WebSocket stream endpoints.
type VideoStreamHandler struct {
	ML     VideoMLClient
	Logger zerolog.Logger
}

// NewVideoStreamHandler returns a handler backed by the given ML client.
// ML may be nil — all frames return UNAVAILABLE in that case.
func NewVideoStreamHandler(mlClient VideoMLClient, logger zerolog.Logger) *VideoStreamHandler {
	return &VideoStreamHandler{
		ML:     mlClient,
		Logger: logger.With().Str("handler", "video").Logger(),
	}
}

// ── Request / response shapes ────────────────────────────────────────

// sessionResponse is returned by POST /api/v1/video/session.
type sessionResponse struct {
	SessionID string `json:"session_id"`
}

// frameRequest is the JSON frame message sent by the WebSocket client.
type frameRequest struct {
	FrameSeq      int64  `json:"frame_seq"`
	FeatureVector string `json:"feature_vector"` // base64-encoded float32 bytes
	FaceDetected  bool   `json:"face_detected"`
}

// frameScore is the per-frame verdict written back over the WebSocket.
type frameScore struct {
	FrameSeq   int64   `json:"frame_seq"`
	Confidence float64 `json:"confidence,omitempty"`
	Verdict    string  `json:"verdict"`
	LatencyMS  float64 `json:"latency_ms,omitempty"`
}

// ── HTTP handlers ────────────────────────────────────────────────────

// CreateSession handles POST /api/v1/video/session.
// It allocates a new session_id and returns it to the caller.
// No persistence — sessions are ephemeral routing keys.
func (h *VideoStreamHandler) CreateSession(w http.ResponseWriter, r *http.Request) {
	sessionID := uuid.NewString()
	h.Logger.Debug().Str("session_id", sessionID).Msg("video session created")
	writeJSON(w, http.StatusOK, sessionResponse{SessionID: sessionID})
}

// Stream handles WS /api/v1/video/stream/{session_id}.
// It upgrades the connection to WebSocket, opens a gRPC bidirectional
// stream to the ML service, and relays frames and scores.
func (h *VideoStreamHandler) Stream(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_session_id", "session_id is required")
		return
	}

	wsHandler := websocket.Handler(func(conn *websocket.Conn) {
		h.handleStream(conn, r.Context(), sessionID)
	})
	wsHandler.ServeHTTP(w, r)
}

// handleStream is the core WebSocket loop. It opens the gRPC stream once
// and then relays each incoming frame to the ML service, writing the
// verdict back over the WebSocket connection.
func (h *VideoStreamHandler) handleStream(
	conn *websocket.Conn,
	ctx context.Context,
	sessionID string,
) {
	logger := h.Logger.With().Str("session_id", sessionID).Logger()
	logger.Info().Msg("video stream opened")
	defer logger.Info().Msg("video stream closed")

	// Attempt to open the gRPC bidirectional stream.
	// ml.ErrMLUnavailable is returned when the breaker is open or ML is
	// disabled — we continue in degraded mode rather than closing the WS.
	var grpcStream mlpb.InferenceService_ScoreVideoStreamClient
	if h.ML != nil {
		var err error
		grpcStream, err = h.ML.ScoreVideoStream(ctx)
		if err != nil {
			logger.Debug().Err(err).Msg("ml stream unavailable; running in degraded mode")
		}
	}

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var frame frameRequest
		if err := decoder.Decode(&frame); err != nil {
			if err == io.EOF {
				break // client closed cleanly
			}
			logger.Debug().Err(err).Msg("ws decode error")
			break
		}

		score := h.scoreFrame(ctx, logger, grpcStream, sessionID, frame)
		if err := encoder.Encode(score); err != nil {
			logger.Debug().Err(err).Msg("ws write error")
			break
		}
	}

	// Close the gRPC stream gracefully if it was opened.
	if grpcStream != nil {
		_ = grpcStream.CloseSend()
	}
}

// scoreFrame sends one frame over the gRPC stream and waits for the
// VideoScoreEvent reply. On any error it returns an UNAVAILABLE verdict
// so the client can distinguish ML-down from a genuine threat score.
func (h *VideoStreamHandler) scoreFrame(
	_ context.Context,
	logger zerolog.Logger,
	grpcStream mlpb.InferenceService_ScoreVideoStreamClient,
	sessionID string,
	frame frameRequest,
) frameScore {
	unavailable := frameScore{
		FrameSeq: frame.FrameSeq,
		Verdict:  "UNAVAILABLE",
	}

	if grpcStream == nil {
		return unavailable
	}

	// Decode the base64 feature vector.
	featureBytes, err := base64.StdEncoding.DecodeString(frame.FeatureVector)
	if err != nil {
		// Try URL-encoding variant (some clients use it).
		featureBytes, err = base64.URLEncoding.DecodeString(frame.FeatureVector)
		if err != nil {
			logger.Warn().
				Int64("frame_seq", frame.FrameSeq).
				Err(err).
				Msg("feature_vector base64 decode failed")
			return unavailable
		}
	}

	req := &mlpb.VideoFrameRequest{
		SessionId:     sessionID,
		FrameSeq:      frame.FrameSeq,
		FrameTsMs:     time.Now().UnixMilli(),
		FeatureVector: featureBytes,
		FaceDetected:  frame.FaceDetected,
	}
	if err := grpcStream.Send(req); err != nil {
		logger.Warn().Int64("frame_seq", frame.FrameSeq).Err(err).Msg("grpc send failed")
		return unavailable
	}

	event, err := grpcStream.Recv()
	if err != nil {
		logger.Warn().Int64("frame_seq", frame.FrameSeq).Err(err).Msg("grpc recv failed")
		return unavailable
	}

	return frameScore{
		FrameSeq:   event.GetFrameSeq(),
		Confidence: event.GetConfidence(),
		Verdict:    event.GetVerdict(),
		LatencyMS:  event.GetLatencyMs(),
	}
}

// Ensure *ml.Client satisfies VideoMLClient at compile time.
var _ VideoMLClient = (*ml.Client)(nil)
