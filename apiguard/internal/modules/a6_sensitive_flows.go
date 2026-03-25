package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/opensecstack/apiguard/internal/domain"
)

// SensitiveFlowModule implements OWASP API6:2023 — Unrestricted Access to Sensitive Business Flows.
type SensitiveFlowModule struct{}

func (m *SensitiveFlowModule) ID() string   { return "a6_business_flow" }
func (m *SensitiveFlowModule) Name() string { return "Unrestricted Access to Sensitive Business Flows" }

// Run executes sensitive business flow test cases from the provided suite against the target.
func (m *SensitiveFlowModule) Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	for _, tc := range suite.Cases {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		switch tc.Category {
		case "sensitive_flow_mass_create":
			f, err := m.runMassCreate(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		case "sensitive_flow_no_captcha_signal":
			f, err := m.runNoCaptchaSignal(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		case "sensitive_flow_replay":
			f, err := m.runReplay(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

// buildMassCreateBody returns a JSON array of 100 copies of the original body object,
// or 100 empty objects if the original body is absent or not a JSON object.
func buildMassCreateBody(original []byte) []byte {
	var item interface{}
	if len(original) > 0 {
		if err := json.Unmarshal(original, &item); err != nil {
			item = map[string]interface{}{}
		}
	} else {
		item = map[string]interface{}{}
	}

	items := make([]interface{}, 100)
	for i := range items {
		items[i] = item
	}

	out, err := json.Marshal(items)
	if err != nil {
		// Fallback to a minimal JSON array.
		return []byte(`[{}]`)
	}
	return out
}

// runMassCreate sends a batch POST/PUT with an array of 100 items and reports MEDIUM if accepted.
func (m *SensitiveFlowModule) runMassCreate(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	method := strings.ToUpper(tc.Method)
	if method != http.MethodPost && method != http.MethodPut {
		return nil, nil
	}

	url := strings.TrimRight(target, "/") + tc.Path
	endpoint := method + " " + tc.Path

	massBody := buildMassCreateBody(tc.Body)

	headers := make(map[string]string)
	for k, v := range tc.Headers {
		headers[k] = v
	}
	headers["Content-Type"] = "application/json"

	resp, err := doRequest(ctx, exec, method, url, headers, massBody, auth)
	if err != nil {
		return nil, fmt.Errorf("mass create request failed: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return []domain.Finding{
			{
				OWASPId:        "API6:2023",
				ModuleID:       m.ID(),
				Title:          "Mass Resource Creation Accepted on " + endpoint,
				Description:    fmt.Sprintf("Endpoint %s accepted a batch request containing 100 items and returned HTTP %d. Unrestricted batch creation can be exploited to exhaust resources or manipulate business flows.", endpoint, resp.StatusCode),
				Severity:       domain.SeverityMedium,
				CVSSScore:      5.3,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
				EndpointPath:   tc.Path,
				EndpointMethod: method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("%s %s (batch array of 100 items)", method, url),
					Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
					Detail: map[string]interface{}{
						"batch_size":  100,
						"status_code": resp.StatusCode,
					},
				},
				Remediation: "Enforce a maximum batch size on endpoints that accept arrays. Validate and limit the number of items per request, and apply rate limiting to creation flows.",
				Status:      domain.FindingStatusOpen,
			},
		}, nil
	}

	return nil, nil
}

// sensitiveFlowPatterns are path substrings that indicate sensitive authentication/registration flows.
var sensitiveFlowPatterns = []string{
	"register", "signup", "login", "forgot", "reset", "verify",
}

// isSensitiveFlowPath returns true if the path matches any sensitive flow pattern.
func isSensitiveFlowPath(path string) bool {
	lower := strings.ToLower(path)
	for _, p := range sensitiveFlowPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// captchaHeaders are response headers that indicate CAPTCHA or bot-protection is active.
var captchaHeaders = []string{
	"x-recaptcha",
	"cf-mitigated",
}

// runNoCaptchaSignal checks for absence of bot-protection signals on sensitive flows.
func (m *SensitiveFlowModule) runNoCaptchaSignal(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	if !isSensitiveFlowPath(tc.Path) {
		return nil, nil
	}

	url := strings.TrimRight(target, "/") + tc.Path
	endpoint := tc.Method + " " + tc.Path

	resp, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, auth)
	if err != nil {
		return nil, fmt.Errorf("captcha signal check request failed: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil
	}

	for _, h := range captchaHeaders {
		if resp.Headers.Get(h) != "" {
			// Bot-protection signal found — no finding.
			return nil, nil
		}
	}

	return []domain.Finding{
		{
			OWASPId:        "API6:2023",
			ModuleID:       m.ID(),
			Title:          "No CAPTCHA / Bot-Protection Signal on Sensitive Endpoint: " + endpoint,
			Description:    fmt.Sprintf("Endpoint %s appears to be a sensitive authentication or registration flow but does not return any CAPTCHA or bot-protection headers (x-recaptcha, cf-mitigated). Automated abuse may be possible.", endpoint),
			Severity:       domain.SeverityInfo,
			CVSSScore:      2.7,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s", tc.Method, url),
				Response: fmt.Sprintf("HTTP %d — no CAPTCHA headers detected", resp.StatusCode),
				Detail: map[string]interface{}{
					"checked_headers": captchaHeaders,
					"status_code":     resp.StatusCode,
					"path_signal":     matchedSensitivePattern(tc.Path),
				},
			},
			Remediation: "Integrate CAPTCHA or bot-protection mechanisms (e.g. reCAPTCHA, Cloudflare Turnstile) on registration, login, and password-reset endpoints to prevent automated abuse.",
			Status:      domain.FindingStatusOpen,
		},
	}, nil
}

// matchedSensitivePattern returns the first sensitive flow keyword found in the path.
func matchedSensitivePattern(path string) string {
	lower := strings.ToLower(path)
	for _, p := range sensitiveFlowPatterns {
		if strings.Contains(lower, p) {
			return p
		}
	}
	return ""
}

// runReplay sends the same POST request twice and reports MEDIUM if both succeed without conflict.
func (m *SensitiveFlowModule) runReplay(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	url := strings.TrimRight(target, "/") + tc.Path
	endpoint := tc.Method + " " + tc.Path

	sendRequest := func() (*HTTPResponse, error) {
		// Ensure the body reader is reset for each request — doRequest creates a new reader from the slice.
		return doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, auth)
	}

	resp1, err := sendRequest()
	if err != nil {
		return nil, fmt.Errorf("replay first request failed: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	resp2, err := sendRequest()
	if err != nil {
		return nil, fmt.Errorf("replay second request failed: %w", err)
	}

	first2xx := resp1.StatusCode == http.StatusOK || resp1.StatusCode == http.StatusCreated
	second2xx := resp2.StatusCode == http.StatusOK || resp2.StatusCode == http.StatusCreated
	hasConflict := resp2.StatusCode == http.StatusConflict

	if first2xx && second2xx && !hasConflict {
		return []domain.Finding{
			{
				OWASPId:        "API6:2023",
				ModuleID:       m.ID(),
				Title:          "Request Replay Accepted Without Idempotency Protection: " + endpoint,
				Description:    fmt.Sprintf("Sending the same POST request to %s twice returned HTTP %d and %d respectively with no conflict response. The endpoint lacks idempotency protection, allowing replay attacks.", endpoint, resp1.StatusCode, resp2.StatusCode),
				Severity:       domain.SeverityMedium,
				CVSSScore:      4.3,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("%s %s (sent twice)", tc.Method, url),
					Response: fmt.Sprintf("First: HTTP %d, Second: HTTP %d — no 409 Conflict", resp1.StatusCode, resp2.StatusCode),
					Detail: map[string]interface{}{
						"first_status":  resp1.StatusCode,
						"second_status": resp2.StatusCode,
						"conflict":      false,
					},
				},
				Remediation: "Implement idempotency keys or duplicate-detection logic. Return HTTP 409 Conflict when the same operation is submitted more than once.",
				Status:      domain.FindingStatusOpen,
			},
		}, nil
	}

	return nil, nil
}

