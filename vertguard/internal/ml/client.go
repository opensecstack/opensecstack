// Package ml wraps the Python ML inference service behind a small,
// breaker-protected client. The Go scanners use this as an optional
// post-step for SUSPICIOUS regex verdicts (Phase 4.2 — see
// docs/ml-integration.md).
//
// SOFT-FAIL contract: every method returns an error but callers MUST
// treat ML failure as "no opinion" — the regex prefilter is the
// authoritative source of truth. Never block a scan on ML being down.
package ml

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/opensecstack/vertguard/internal/breaker"
	mlpb "github.com/opensecstack/vertguard/internal/ml/pb"
)

// ErrMLUnavailable is returned when the breaker is open. Callers
// fall back to regex-only verdicts on this sentinel — never wrap.
var ErrMLUnavailable = errors.New("ml: service unavailable (breaker open)")

// Config tunes the client.
type Config struct {
	GRPCURL     string        // e.g. "localhost:50051"
	Timeout     time.Duration // per-call deadline; default 1s
	Enabled     bool          // master kill switch
	AlwaysScore bool          // call ML on every request, not just SUSPICIOUS
}

// Metrics is the surface the client emits to. Implementations live in
// internal/metrics/adapter.go so the client doesn't import Prometheus.
type Metrics interface {
	IncMLCall(rpc, result string)
	ObserveMLLatency(rpc string, sec float64)
	IncBreakerOpen(rpc string)
}

// noopMetrics keeps the call sites unconditional when no adapter wired.
type noopMetrics struct{}

func (noopMetrics) IncMLCall(string, string)            {}
func (noopMetrics) ObserveMLLatency(string, float64)    {}
func (noopMetrics) IncBreakerOpen(string)               {}

// Result mirrors mlpb.ScoreResponse but lives in this package so
// callers don't need a transitive proto import.
type Result struct {
	Confidence   float64
	Verdict      string // CLEAN | SUSPICIOUS | BLOCKED
	LatencyMs    float64
	ModelVersion string
	InputHash    string
	TopFeatures  []FeatureWeight
}

// FeatureWeight is the package-local mirror of mlpb.FeatureWeight.
type FeatureWeight struct {
	Name   string
	Weight float64
}

// ModelInfo is the package-local mirror of mlpb.ModelInfoResponse.
type ModelInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	TrainingSummary string `json:"training_summary"`
	LoadedAt        int64  `json:"loaded_at"`
	Backend         string `json:"backend"`
	EvalMetricsJson string `json:"eval_metrics_json"`
}

// Client is the soft-failing front-door to the Python ML service.
type Client struct {
	cfg     Config
	conn    *grpc.ClientConn
	stub    mlpb.InferenceServiceClient
	breaker *breaker.Breaker
	metrics Metrics
	logger  zerolog.Logger
}

// New dials the ML service and returns a ready client. Caller closes
// via Close().
//
// TLS: insecure transport for now. Phase 4.2.1 follow-up will add mTLS
// once the ML service exposes a CA bundle (see VG-ML-002 in ROADMAP).
func New(cfg Config, logger zerolog.Logger, metrics Metrics) (*Client, error) {
	if cfg.GRPCURL == "" {
		return nil, fmt.Errorf("ml: grpc_url is empty")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 1 * time.Second
	}
	if metrics == nil {
		metrics = noopMetrics{}
	}

	// WithBlock would deadline-fail boot when the ML service is down;
	// we want non-blocking dial + breaker-driven fallback at runtime.
	conn, err := grpc.NewClient(
		cfg.GRPCURL,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("ml: dial %s: %w", cfg.GRPCURL, err)
	}

	br := breaker.New(breaker.Config{
		Name:          "ml",
		FailThreshold: 5,
		CoolDown:      30 * time.Second,
	})

	return &Client{
		cfg:     cfg,
		conn:    conn,
		stub:    mlpb.NewInferenceServiceClient(conn),
		breaker: br,
		metrics: metrics,
		logger:  logger,
	}, nil
}

// Close releases the gRPC connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// AlwaysScore reports whether ML should run on every verdict, not just SUSPICIOUS.
func (c *Client) AlwaysScore() bool {
	if c == nil {
		return false
	}
	return c.cfg.AlwaysScore
}

// ScorePrompt asks the ML service for a prompt-injection verdict.
// Returns ErrMLUnavailable when the breaker is open.
func (c *Client) ScorePrompt(ctx context.Context, input, contextTag, correlationID, tenant string) (*Result, error) {
	return c.scorePrompt(ctx, input, contextTag, correlationID, tenant)
}

func (c *Client) scorePrompt(ctx context.Context, input, contextTag, correlationID, tenant string) (*Result, error) {
	const rpc = "score_prompt"
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	start := time.Now()

	var resp *mlpb.ScoreResponse
	err := c.breaker.Execute(func() error {
		out, err := c.stub.ScorePrompt(cctx, &mlpb.PromptScoreRequest{
			Input:         input,
			Context:       contextTag,
			CorrelationId: correlationID,
			Tenant:        tenant,
		})
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	c.metrics.ObserveMLLatency(rpc, time.Since(start).Seconds())
	return c.finishScore(rpc, resp, err)
}

// ScorePhishing asks the ML service for a phishing verdict.
func (c *Client) ScorePhishing(ctx context.Context, input, kind, correlationID, tenant string) (*Result, error) {
	const rpc = "score_phishing"
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	start := time.Now()

	var resp *mlpb.ScoreResponse
	err := c.breaker.Execute(func() error {
		out, err := c.stub.ScorePhishing(cctx, &mlpb.PhishingScoreRequest{
			Input:         input,
			Kind:          kind,
			CorrelationId: correlationID,
			Tenant:        tenant,
		})
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	c.metrics.ObserveMLLatency(rpc, time.Since(start).Seconds())
	return c.finishScore(rpc, resp, err)
}

// ScoreMedia asks the ML service for a media authenticity / deepfake verdict.
// Returns ErrMLUnavailable when the breaker is open.
// Phase 4.2: requires media ML weights deployed at VERTGUARD_ML_MEDIA_MODEL_DIR.
func (c *Client) ScoreMedia(ctx context.Context, fileHash, mimeType string, fileSize int64, hasC2PA, c2paValid bool, correlationID, tenant string) (*Result, error) {
	const rpc = mlpb.InferenceService_ScoreMedia_FullMethodName
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	start := time.Now()

	var resp *mlpb.ScoreResponse
	err := c.breaker.Execute(func() error {
		out, err := c.stub.ScoreMedia(cctx, &mlpb.MediaScoreRequest{
			FileHash:           fileHash,
			MimeType:           mimeType,
			FileSize:           fileSize,
			HasC2PaManifest:    hasC2PA,
			C2PaSignatureValid: c2paValid,
			CorrelationId:      correlationID,
			Tenant:             tenant,
		})
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	c.metrics.ObserveMLLatency(rpc, time.Since(start).Seconds())
	return c.finishScore(rpc, resp, err)
}

// ScoreIdentity asks the ML service for a synthetic-identity verdict.
// Returns ErrMLUnavailable when the breaker is open.
// Phase 4.3: requires identity ML weights deployed at VERTGUARD_ML_IDENTITY_MODEL_DIR.
func (c *Client) ScoreIdentity(ctx context.Context, claimType, contextTag string, nameTokenCount int32, emailDisposable, idFormatValid bool, issuerCountry string, hasDOB bool, replayCount int32, correlationID, tenant string) (*Result, error) {
	const rpc = mlpb.InferenceService_ScoreIdentity_FullMethodName
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	start := time.Now()

	var resp *mlpb.ScoreResponse
	err := c.breaker.Execute(func() error {
		out, err := c.stub.ScoreIdentity(cctx, &mlpb.IdentityScoreRequest{
			ClaimType:               claimType,
			Context:                 contextTag,
			NameTokenCount:          nameTokenCount,
			EmailDomainIsDisposable: emailDisposable,
			IdFormatValid:           idFormatValid,
			IssuerCountry:           issuerCountry,
			HasDob:                  hasDOB,
			ReplayCount:             replayCount,
			CorrelationId:           correlationID,
			Tenant:                  tenant,
		})
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	c.metrics.ObserveMLLatency(rpc, time.Since(start).Seconds())
	return c.finishScore(rpc, resp, err)
}

// ScoreAudio asks the ML service for a voice clone verdict.
// Returns ErrMLUnavailable when the breaker is open.
// Phase 4.3: requires audio ML weights deployed at VERTGUARD_ML_AUDIO_MODEL_DIR.
func (c *Client) ScoreAudio(ctx context.Context, sessionID string, mfccHash, spectralHash []byte, durationMs float32, voiceDetected bool, correlationID, tenant string) (*Result, error) {
	const rpc = mlpb.InferenceService_ScoreAudio_FullMethodName
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	start := time.Now()

	var resp *mlpb.ScoreResponse
	err := c.breaker.Execute(func() error {
		out, err := c.stub.ScoreAudio(cctx, &mlpb.AudioScoreRequest{
			SessionId:     sessionID,
			MfccHash:      mfccHash,
			SpectralHash:  spectralHash,
			DurationMs:    durationMs,
			VoiceDetected: voiceDetected,
			CorrelationId: correlationID,
			Tenant:        tenant,
		})
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	c.metrics.ObserveMLLatency(rpc, time.Since(start).Seconds())
	return c.finishScore(rpc, resp, err)
}

// ScoreVideoStream opens a bidirectional stream for real-time video deepfake detection.
// The caller sends VideoFrameRequest messages and receives VideoScoreEvent replies.
// Returns ErrMLUnavailable when the breaker is open.
func (c *Client) ScoreVideoStream(ctx context.Context) (mlpb.InferenceService_ScoreVideoStreamClient, error) {
	const rpc = "score_video_stream"
	if c == nil || !c.cfg.Enabled {
		return nil, ErrMLUnavailable
	}
	if c.breaker.State() == breaker.StateOpen {
		c.metrics.IncBreakerOpen(rpc)
		return nil, ErrMLUnavailable
	}
	stream, err := c.stub.ScoreVideoStream(ctx)
	if err != nil {
		c.metrics.IncMLCall(rpc, classifyErr(err))
		return nil, err
	}
	c.metrics.IncMLCall(rpc, "ok")
	return stream, nil
}

// ModelInfo asks the ML service which model is currently loaded.
// Used by the admin endpoint; not on the scan hot-path.
func (c *Client) ModelInfo(ctx context.Context) (*ModelInfo, error) {
	const rpc = "model_info"
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	start := time.Now()

	var resp *mlpb.ModelInfoResponse
	err := c.breaker.Execute(func() error {
		out, err := c.stub.ModelInfo(cctx, &mlpb.ModelInfoRequest{})
		if err != nil {
			return err
		}
		resp = out
		return nil
	})
	c.metrics.ObserveMLLatency(rpc, time.Since(start).Seconds())
	if errors.Is(err, breaker.ErrOpen) {
		c.metrics.IncMLCall(rpc, "breaker_open")
		c.metrics.IncBreakerOpen(rpc)
		return nil, ErrMLUnavailable
	}
	if err != nil {
		c.metrics.IncMLCall(rpc, classifyErr(err))
		return nil, err
	}
	c.metrics.IncMLCall(rpc, "ok")
	return &ModelInfo{
		Name:            resp.GetName(),
		Version:         resp.GetVersion(),
		TrainingSummary: resp.GetTrainingSummary(),
		LoadedAt:        resp.GetLoadedAt(),
		Backend:         resp.GetBackend(),
		EvalMetricsJson: resp.GetEvalMetricsJson(),
	}, nil
}

func (c *Client) finishScore(rpc string, resp *mlpb.ScoreResponse, err error) (*Result, error) {
	if errors.Is(err, breaker.ErrOpen) {
		c.metrics.IncMLCall(rpc, "breaker_open")
		c.metrics.IncBreakerOpen(rpc)
		return nil, ErrMLUnavailable
	}
	if err != nil {
		c.metrics.IncMLCall(rpc, classifyErr(err))
		return nil, err
	}
	c.metrics.IncMLCall(rpc, "ok")
	out := &Result{
		Confidence:   resp.GetConfidence(),
		Verdict:      resp.GetVerdict(),
		LatencyMs:    resp.GetLatencyMs(),
		ModelVersion: resp.GetModelVersion(),
		InputHash:    resp.GetInputHash(),
	}
	for _, f := range resp.TopFeatures {
		out.TopFeatures = append(out.TopFeatures, FeatureWeight{
			Name: f.GetName(), Weight: f.GetWeight(),
		})
	}
	return out, nil
}

func classifyErr(err error) string {
	if err == nil {
		return "ok"
	}
	// context.DeadlineExceeded is the canonical timeout signal.
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "fail"
}

