package modules

import (
	"context"
	"testing"

	"github.com/opensecstack/apiguard/internal/domain"
)

// TestRateLimitBurstFinding verifies that a HIGH finding is produced when all 20 burst
// requests succeed without any 429/503 response.
func TestRateLimitBurstFinding(t *testing.T) {
	// runBurst sends 1 baseline + 20 burst requests = 21 total.
	// All return 200 → successCount = 20 >= 18 → HIGH finding.
	responses := make([]*HTTPResponse, 21)
	for i := range responses {
		responses[i] = resp(200, `{"ok":true}`)
	}

	exec := &mockExecutor{responses: responses}

	mod := &RateLimitModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc1",
				Category: "rate_limit_burst",
				Method:   "GET",
				Path:     "/api/items",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}
	if findings[0].Severity != domain.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
}

// TestRateLimitBurstNoFinding verifies that no finding is produced when the server returns
// at least one 429 during the burst (rate limiting is working).
func TestRateLimitBurstNoFinding(t *testing.T) {
	// Baseline returns 200, first burst request returns 429 → rateLimitDetected = true → no finding.
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"ok":true}`), // baseline
			resp(429, ``),            // first burst → rate limit detected
		},
	}

	mod := &RateLimitModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc2",
				Category: "rate_limit_burst",
				Method:   "GET",
				Path:     "/api/items",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// TestRateLimitHeaderCheckFinding verifies that an INFO finding is produced when the
// response has no rate limit headers.
func TestRateLimitHeaderCheckFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"ok":true}`), // no rate limit headers
		},
	}

	mod := &RateLimitModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc3",
				Category: "rate_limit_no_header",
				Method:   "GET",
				Path:     "/api/items",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding, got none")
	}
	if findings[0].Severity != domain.SeverityInfo {
		t.Errorf("expected INFO severity, got %s", findings[0].Severity)
	}
}

// TestRateLimitHeaderCheckNoFinding verifies that no finding is produced when the response
// includes a rate limit header.
func TestRateLimitHeaderCheckNoFinding(t *testing.T) {
	exec := &mockExecutor{
		responses: []*HTTPResponse{
			resp(200, `{"ok":true}`, "X-RateLimit-Limit", "100"),
		},
	}

	mod := &RateLimitModule{}
	suite := TestSuite{
		Cases: []TestCase{
			{
				ID:       "tc4",
				Category: "rate_limit_no_header",
				Method:   "GET",
				Path:     "/api/items",
			},
		},
	}

	findings, err := mod.Run(context.Background(), exec, suite, "http://example.com", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

// TestRateLimitIDAndName verifies the module ID and Name.
func TestRateLimitIDAndName(t *testing.T) {
	mod := &RateLimitModule{}
	if mod.ID() != "a4_rate_limit" {
		t.Errorf("expected ID a4_rate_limit, got %s", mod.ID())
	}
	if mod.Name() == "" {
		t.Error("expected non-empty Name()")
	}
}
