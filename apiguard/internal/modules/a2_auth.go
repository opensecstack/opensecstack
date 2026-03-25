package modules

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/opensecstack/apiguard/internal/domain"
)

// AuthModule implements OWASP API2:2023 Broken Authentication checks.
type AuthModule struct{}

// ID returns the unique identifier for this module.
func (m *AuthModule) ID() string { return "a2_auth" }

// Name returns the human-readable name of this module.
func (m *AuthModule) Name() string { return "Broken Authentication" }

// Run executes all authentication test cases and returns any findings discovered.
func (m *AuthModule) Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	for _, tc := range suite.Cases {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		switch tc.Category {
		case "auth_removal":
			f, err := m.executeAuthRemoval(ctx, exec, tc, target)
			if err != nil {
				continue
			}
			if f != nil {
				findings = append(findings, *f)
			}
		case "auth_token_expired":
			f, err := m.executeExpiredToken(ctx, exec, tc, target)
			if err != nil {
				continue
			}
			if f != nil {
				findings = append(findings, *f)
			}
		case "auth_invalid_token":
			f, err := m.executeInvalidToken(ctx, exec, tc, target)
			if err != nil {
				continue
			}
			if f != nil {
				findings = append(findings, *f)
			}
		case "auth_unprotected_write":
			f, err := m.executeUnprotectedWrite(ctx, exec, tc, target)
			if err != nil {
				continue
			}
			if f != nil {
				findings = append(findings, *f)
			}
		}
	}

	return findings, nil
}

// executeAuthRemoval sends a request without authentication.
// If the server responds with 2xx, the endpoint is accessible without auth (CRITICAL).
func (m *AuthModule) executeAuthRemoval(ctx context.Context, exec HTTPExecutor, tc TestCase, target string) (*domain.Finding, error) {
	url := buildURL(target, tc.Path, "1")
	resp, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, nil)
	if err != nil {
		return nil, fmt.Errorf("auth removal request failed: %w", err)
	}

	endpoint := tc.Method + " " + tc.Path

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &domain.Finding{
			OWASPId:        "API2:2023",
			ModuleID:       "a2_auth",
			Title:          "Missing Authentication on " + endpoint,
			Description:    fmt.Sprintf("The endpoint %s returned HTTP %d without any authentication credentials. The endpoint is accessible to unauthenticated users.", endpoint, resp.StatusCode),
			Severity:       domain.SeverityCritical,
			CVSSScore:      9.1,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s (no auth)", tc.Method, url),
				Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
				Detail: map[string]interface{}{
					"auth_type":   "none",
					"status_code": resp.StatusCode,
				},
			},
			Remediation: "Enforce authentication on all sensitive endpoints. Ensure auth middleware is applied before any business logic.",
			Status:      domain.FindingStatusOpen,
		}, nil
	}

	return nil, nil
}

// executeExpiredToken sends a request with an expired JWT token.
// If the server responds with 2xx, expired tokens are accepted (HIGH).
func (m *AuthModule) executeExpiredToken(ctx context.Context, exec HTTPExecutor, tc TestCase, target string) (*domain.Finding, error) {
	url := buildURL(target, tc.Path, "1")

	expiredAuth := &AuthConfig{
		Type:  "bearer",
		Token: generateExpiredJWT(),
	}

	resp, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, expiredAuth)
	if err != nil {
		return nil, fmt.Errorf("expired token request failed: %w", err)
	}

	endpoint := tc.Method + " " + tc.Path

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &domain.Finding{
			OWASPId:        "API2:2023",
			ModuleID:       "a2_auth",
			Title:          "Expired Token Accepted on " + endpoint,
			Description:    fmt.Sprintf("The endpoint %s returned HTTP %d when presented with an expired JWT token. The server is not validating token expiration.", endpoint, resp.StatusCode),
			Severity:       domain.SeverityHigh,
			CVSSScore:      7.4,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s (expired JWT)", tc.Method, url),
				Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
				Detail: map[string]interface{}{
					"auth_type":   "bearer",
					"status_code": resp.StatusCode,
				},
			},
			Remediation: "Validate token expiration (exp claim) on every request. Reject tokens with expired timestamps.",
			Status:      domain.FindingStatusOpen,
		}, nil
	}

	return nil, nil
}

// executeInvalidToken sends a request with a malformed/invalid token.
// If the server responds with 2xx, invalid tokens are accepted (CRITICAL).
func (m *AuthModule) executeInvalidToken(ctx context.Context, exec HTTPExecutor, tc TestCase, target string) (*domain.Finding, error) {
	url := buildURL(target, tc.Path, "1")

	invalidAuth := &AuthConfig{
		Type:  "bearer",
		Token: "invalid-token-xxx",
	}

	resp, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, invalidAuth)
	if err != nil {
		return nil, fmt.Errorf("invalid token request failed: %w", err)
	}

	endpoint := tc.Method + " " + tc.Path

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &domain.Finding{
			OWASPId:        "API2:2023",
			ModuleID:       "a2_auth",
			Title:          "Invalid Token Accepted on " + endpoint,
			Description:    fmt.Sprintf("The endpoint %s returned HTTP %d when presented with a malformed token. The server is not properly validating token signatures or format.", endpoint, resp.StatusCode),
			Severity:       domain.SeverityCritical,
			CVSSScore:      9.1,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s (invalid token)", tc.Method, url),
				Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
				Detail: map[string]interface{}{
					"auth_type":   "bearer",
					"status_code": resp.StatusCode,
				},
			},
			Remediation: "Validate token signatures and format. Reject malformed or unsigned tokens.",
			Status:      domain.FindingStatusOpen,
		}, nil
	}

	return nil, nil
}

// executeUnprotectedWrite sends a state-changing request without auth.
// If the server responds with 2xx, the write endpoint lacks authentication (MEDIUM).
func (m *AuthModule) executeUnprotectedWrite(ctx context.Context, exec HTTPExecutor, tc TestCase, target string) (*domain.Finding, error) {
	method := tc.Method
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return nil, nil
	}

	url := strings.TrimRight(target, "/") + tc.Path

	resp, err := doRequest(ctx, exec, method, url, tc.Headers, tc.Body, nil)
	if err != nil {
		return nil, fmt.Errorf("unprotected write request failed: %w", err)
	}

	endpoint := method + " " + tc.Path

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return &domain.Finding{
			OWASPId:        "API2:2023",
			ModuleID:       "a2_auth",
			Title:          "Unprotected State-Changing Endpoint: " + endpoint,
			Description:    fmt.Sprintf("The state-changing endpoint %s returned HTTP %d without authentication. State-changing operations should require authentication.", endpoint, resp.StatusCode),
			Severity:       domain.SeverityMedium,
			CVSSScore:      5.3,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
			EndpointPath:   tc.Path,
			EndpointMethod: method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s (no auth)", method, url),
				Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
				Detail: map[string]interface{}{
					"auth_type":   "none",
					"status_code": resp.StatusCode,
				},
			},
			Remediation: "Review whether this endpoint should require authentication. State-changing operations (POST/PUT/PATCH/DELETE) typically need auth.",
			Status:      domain.FindingStatusOpen,
		}, nil
	}

	return nil, nil
}

// generateExpiredJWT creates a JWT token with an expiration time in the past.
func generateExpiredJWT() string {
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(fmt.Sprintf(
		`{"sub":"test-user","iat":%d,"exp":%d}`,
		time.Now().Add(-2*time.Hour).Unix(),
		time.Now().Add(-1*time.Hour).Unix(),
	)))
	signingInput := header + "." + payload
	sig := hmacSHA256([]byte("apiguard-test-key"), []byte(signingInput))
	return signingInput + "." + base64URLEncode(sig)
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
