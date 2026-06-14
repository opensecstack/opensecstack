// Adapters that make the package's Client implement the MLEnricher
// interfaces of prompt and phishing without forcing those packages to
// import this one (avoids a circular dependency at the proto/grpc
// dependency boundary).
//
// The adapter pattern (vs. defining MLEnricher here) keeps the
// scanner packages testable with simple fakes — see scanner_test.go.

package ml

import (
	"context"

	"github.com/opensecstack/vertguard/internal/phishing"
	"github.com/opensecstack/vertguard/internal/prompt"
)

// MediaEnricher adapts Client → handlers.MediaMLEnricher.
// It forwards ScoreMedia calls to the gRPC ML service and soft-fails on error.
type MediaEnricher struct{ C *Client }

// ScoreMedia implements handlers.MediaMLEnricher.
func (e MediaEnricher) ScoreMedia(ctx context.Context, fileHash, mimeType string, fileSize int64, hasC2PA, c2paValid bool, correlationID, tenant string) (*Result, error) {
	if e.C == nil {
		return nil, nil
	}
	return e.C.ScoreMedia(ctx, fileHash, mimeType, fileSize, hasC2PA, c2paValid, correlationID, tenant)
}

// AlwaysScore exposes the operator preference to the handler.
func (e MediaEnricher) AlwaysScore() bool {
	if e.C == nil {
		return false
	}
	return e.C.AlwaysScore()
}

// PromptEnricher adapts Client → prompt.MLEnricher.
type PromptEnricher struct{ C *Client }

// Score implements prompt.MLEnricher. Returns nil on any error so the
// scanner soft-fails to regex-only.
func (p PromptEnricher) Score(ctx context.Context, input, contextTag string) (*prompt.MLScore, error) {
	if p.C == nil {
		return nil, nil
	}
	r, err := p.C.ScorePrompt(ctx, input, contextTag, "", "")
	if err != nil || r == nil {
		return nil, err
	}
	return &prompt.MLScore{
		Confidence:   r.Confidence,
		Verdict:      r.Verdict,
		ModelVersion: r.ModelVersion,
	}, nil
}

// AlwaysScore exposes the operator preference to the scanner.
func (p PromptEnricher) AlwaysScore() bool {
	if p.C == nil {
		return false
	}
	return p.C.AlwaysScore()
}

// AudioEnricher adapts Client → handlers.AudioMLEnricher.
// It forwards ScoreAudio calls to the gRPC ML service and soft-fails on error.
type AudioEnricher struct{ C *Client }

// ScoreAudio implements handlers.AudioMLEnricher.
func (e AudioEnricher) ScoreAudio(ctx context.Context, sessionID string, mfccHash, spectralHash []byte, durationMs float32, voiceDetected bool, correlationID, tenant string) (*Result, error) {
	if e.C == nil {
		return nil, nil
	}
	return e.C.ScoreAudio(ctx, sessionID, mfccHash, spectralHash, durationMs, voiceDetected, correlationID, tenant)
}

// AlwaysScore exposes the operator preference to the handler.
func (e AudioEnricher) AlwaysScore() bool {
	if e.C == nil {
		return false
	}
	return e.C.AlwaysScore()
}

// PhishingEnricher adapts Client → phishing.MLEnricher.
type PhishingEnricher struct{ C *Client }

// ScorePhishing implements phishing.MLEnricher.
func (p PhishingEnricher) ScorePhishing(ctx context.Context, input, kind string) (*phishing.MLScore, error) {
	if p.C == nil {
		return nil, nil
	}
	r, err := p.C.ScorePhishing(ctx, input, kind, "", "")
	if err != nil || r == nil {
		return nil, err
	}
	return &phishing.MLScore{
		Confidence:   r.Confidence,
		Verdict:      r.Verdict,
		ModelVersion: r.ModelVersion,
	}, nil
}

// AlwaysScore exposes the operator preference.
func (p PhishingEnricher) AlwaysScore() bool {
	if p.C == nil {
		return false
	}
	return p.C.AlwaysScore()
}
