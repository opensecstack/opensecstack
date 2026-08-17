package ml

import (
	"context"
	"math"
	"strings"

	"github.com/opensecstack/vertguard/internal/identity"
)

// IdentityAdapter wraps *Client so it satisfies identity.MLEnricher.
// It translates ClaimRequest → IdentityScoreRequest fields before the
// gRPC call, and *Result → *identity.MLScore on the way back.
type IdentityAdapter struct {
	client *Client
}

// NewIdentityAdapter wraps c as an identity.MLEnricher. Returns nil
// when c is nil so callers can pass it directly as an optional field.
func NewIdentityAdapter(c *Client) *IdentityAdapter {
	if c == nil {
		return nil
	}
	return &IdentityAdapter{client: c}
}

// AlwaysScore delegates to the underlying client config.
func (a *IdentityAdapter) AlwaysScore() bool {
	return a.client.AlwaysScore()
}

// ScoreIdentity satisfies identity.MLEnricher.
func (a *IdentityAdapter) ScoreIdentity(ctx context.Context, claim identity.ClaimRequest) (*identity.MLScore, error) {
	// Derive non-PII signals from the claim fields.
	nameTokens := countTokens(claim.Fields["name"])
	emailDisposable := false // The Go rule engine already checked; we pass false here
	// since the ML service has its own blocklist.
	idFormatValid := true // Optimistic default; ML refines on top of rules.
	issuerCountry := strings.ToUpper(claim.Fields["issuer_country"])
	hasDOB := claim.Fields["dob"] != ""
	replayCount := int32(0) // Replay state lives in the scanner; pass 0 to ML.

	result, err := a.client.ScoreIdentity(
		ctx,
		string(claim.ClaimType),
		string(claim.Context),
		clampInt32(nameTokens),
		emailDisposable,
		idFormatValid,
		issuerCountry,
		hasDOB,
		replayCount,
		"", // correlationID — scanner does not surface it here
		"", // tenant — handler sets this at the client level
	)
	if err != nil {
		return nil, err
	}
	return &identity.MLScore{
		Confidence:   result.Confidence,
		Verdict:      result.Verdict,
		ModelVersion: result.ModelVersion,
		LatencyMs:    result.LatencyMs,
	}, nil
}

// countTokens splits on whitespace/hyphen/apostrophe, returns token count.
// clampInt32 caps a derived count (e.g. token counts from user-supplied
// name fields) to the int32 range required by the gRPC wire type,
// instead of letting the conversion wrap silently. Request bodies are
// bounded well below int32 range (see internal/api/handlers helpers.go
// MaxBytesReader defaults), so this is a defensive backstop, not a
// path that fires in practice.
func clampInt32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n)
}

func countTokens(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	inToken := false
	for _, r := range s {
		if r == ' ' || r == '-' || r == '\'' {
			inToken = false
		} else {
			if !inToken {
				n++
			}
			inToken = true
		}
	}
	return n
}
