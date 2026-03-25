package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/opensecstack/apiguard/internal/domain"
)

// RateLimitModule implements OWASP API4:2023 — Unrestricted Resource Consumption.
type RateLimitModule struct{}

func (m *RateLimitModule) ID() string   { return "a4_rate_limit" }
func (m *RateLimitModule) Name() string { return "Unrestricted Resource Consumption" }

// Run executes rate limiting test cases from the provided suite against the target.
func (m *RateLimitModule) Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	for _, tc := range suite.Cases {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		switch tc.Category {
		case "rate_limit_burst":
			f, err := m.runBurst(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		case "rate_limit_no_header":
			f, err := m.runHeaderCheck(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

// runBurst sends 20 rapid requests and reports a HIGH finding if no rate limiting is detected.
func (m *RateLimitModule) runBurst(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	url := strings.TrimRight(target, "/") + tc.Path

	// Baseline request to verify the endpoint is reachable and returns 2xx with auth.
	baseline, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, auth)
	if err != nil {
		return nil, fmt.Errorf("burst baseline request failed: %w", err)
	}
	if baseline.StatusCode < 200 || baseline.StatusCode >= 300 {
		// Endpoint is not returning 2xx even with auth — skip test.
		return nil, nil
	}

	const burstCount = 20
	successCount := 0
	rateLimitDetected := false

	for i := 0; i < burstCount; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, auth)
		if err != nil {
			continue
		}

		switch resp.StatusCode {
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			rateLimitDetected = true
		default:
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				successCount++
			}
		}
	}

	if rateLimitDetected {
		// Server enforced rate limiting — no finding.
		return nil, nil
	}

	endpoint := tc.Method + " " + tc.Path

	if successCount >= 18 {
		return []domain.Finding{
			{
				OWASPId:        "API4:2023",
				ModuleID:       m.ID(),
				Title:          "No Rate Limiting Detected on " + endpoint,
				Description:    fmt.Sprintf("Endpoint %s accepted all %d rapid successive requests without returning HTTP 429 or 503. No rate limiting is enforced, allowing unrestricted resource consumption.", endpoint, successCount),
				Severity:       domain.SeverityHigh,
				CVSSScore:      7.5,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("%s %s (burst x%d)", tc.Method, url, burstCount),
					Response: fmt.Sprintf("%d/%d requests returned 2xx — no 429 observed", successCount, burstCount),
					Detail: map[string]interface{}{
						"burst_count":   burstCount,
						"success_count": successCount,
						"rate_limited":  false,
					},
				},
				Remediation: "Implement rate limiting on all API endpoints. Return HTTP 429 with Retry-After header when limits are exceeded. Consider per-user and per-IP throttling.",
				Status:      domain.FindingStatusOpen,
			},
		}, nil
	}

	return nil, nil
}

// runHeaderCheck sends a single request and reports an INFO finding if rate limit headers are absent.
func (m *RateLimitModule) runHeaderCheck(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	url := strings.TrimRight(target, "/") + tc.Path

	resp, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, auth)
	if err != nil {
		return nil, fmt.Errorf("rate limit header check request failed: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil
	}

	rateLimitHeaders := []string{
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"RateLimit-Limit",
		"Retry-After",
	}

	for _, h := range rateLimitHeaders {
		if resp.Headers.Get(h) != "" {
			// At least one rate limit header is present — no finding.
			return nil, nil
		}
	}

	endpoint := tc.Method + " " + tc.Path

	return []domain.Finding{
		{
			OWASPId:        "API4:2023",
			ModuleID:       m.ID(),
			Title:          "Missing Rate Limit Headers on " + endpoint,
			Description:    fmt.Sprintf("Endpoint %s does not return any rate limit headers (X-RateLimit-*, RateLimit-*, Retry-After). Clients have no indication of rate limit policies.", endpoint),
			Severity:       domain.SeverityInfo,
			CVSSScore:      0.0,
			CVSSVector:     "",
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s", tc.Method, url),
				Response: fmt.Sprintf("HTTP %d — no rate limit headers found", resp.StatusCode),
				Detail: map[string]interface{}{
					"checked_headers": rateLimitHeaders,
					"status_code":     resp.StatusCode,
				},
			},
			Remediation: "Add rate limit response headers (e.g. X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After) so clients can adapt their request rates.",
			Status:      domain.FindingStatusOpen,
		},
	}, nil
}
