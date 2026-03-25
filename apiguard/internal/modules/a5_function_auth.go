package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/opensecstack/apiguard/internal/cvss"
	"github.com/opensecstack/apiguard/internal/domain"
)

// FunctionAuthModule implements OWASP API5:2023 — Broken Function Level Authorization.
type FunctionAuthModule struct{}

func (m *FunctionAuthModule) ID() string   { return "a5_function_auth" }
func (m *FunctionAuthModule) Name() string { return "Broken Function Level Authorization" }

// Run executes function-level authorization test cases from the provided suite against the target.
func (m *FunctionAuthModule) Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	for _, tc := range suite.Cases {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		switch tc.Category {
		case "function_auth_admin_endpoint":
			f, err := m.runAdminEndpoint(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		case "function_auth_http_method_swap":
			f, err := m.runMethodSwap(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		case "function_auth_privilege_escalation":
			f, err := m.runPrivilegeEscalation(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

// adminSegments are path substrings that indicate administrative or privileged endpoints.
var adminSegments = []string{
	"admin", "manage", "internal", "config", "settings", "users", "roles", "permissions",
}

// isAdminPath returns true if the path contains any admin-looking segment.
func isAdminPath(path string) bool {
	lower := strings.ToLower(path)
	for _, seg := range adminSegments {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	return false
}

// runAdminEndpoint tests whether administrative endpoints are accessible without auth or with a regular token.
func (m *FunctionAuthModule) runAdminEndpoint(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	if !isAdminPath(tc.Path) {
		return nil, nil
	}

	url := strings.TrimRight(target, "/") + tc.Path
	endpoint := tc.Method + " " + tc.Path
	var findings []domain.Finding

	// Test 1: access without any authentication.
	respNoAuth, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, nil)
	if err != nil {
		return nil, fmt.Errorf("admin endpoint unauthenticated request failed: %w", err)
	}

	if respNoAuth.StatusCode >= 200 && respNoAuth.StatusCode < 300 {
		findings = append(findings, domain.Finding{
			OWASPId:        "API5:2023",
			ModuleID:       m.ID(),
			Title:          "Admin Endpoint Accessible Without Authentication: " + endpoint,
			Description:    fmt.Sprintf("The administrative endpoint %s returned HTTP %d without any authentication credentials. Administrative endpoints must require authentication.", endpoint, respNoAuth.StatusCode),
			Severity:       domain.SeverityCritical,
			CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s (no auth)", tc.Method, url),
				Response: fmt.Sprintf("HTTP %d", respNoAuth.StatusCode),
				Detail: map[string]interface{}{
					"auth_type":   "none",
					"status_code": respNoAuth.StatusCode,
					"path_signal": matchedAdminSegment(tc.Path),
				},
			},
			Remediation: "Restrict administrative endpoints to privileged roles. Enforce authentication and role-based access control (RBAC) on all admin routes.",
			Status:      domain.FindingStatusOpen,
		})
	}

	// Test 2: access with a regular user token (potential privilege escalation).
	if auth != nil {
		respWithAuth, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, auth)
		if err != nil {
			return findings, nil
		}

		if respWithAuth.StatusCode >= 200 && respWithAuth.StatusCode < 300 {
			findings = append(findings, domain.Finding{
				OWASPId:        "API5:2023",
				ModuleID:       m.ID(),
				Title:          "Admin Endpoint Accessible With Regular User Token: " + endpoint,
				Description:    fmt.Sprintf("The administrative endpoint %s returned HTTP %d when accessed with a regular user token. Function-level authorization is not enforced.", endpoint, respWithAuth.StatusCode),
				Severity:       domain.SeverityMedium,
				CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"),
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("%s %s (regular user token)", tc.Method, url),
					Response: fmt.Sprintf("HTTP %d", respWithAuth.StatusCode),
					Detail: map[string]interface{}{
						"auth_type":   auth.Type,
						"status_code": respWithAuth.StatusCode,
						"path_signal": matchedAdminSegment(tc.Path),
					},
				},
				Remediation: "Implement function-level authorization checks. Verify that the caller has admin or privileged role before processing requests to administrative endpoints.",
				Status:      domain.FindingStatusOpen,
			})
		}
	}

	return findings, nil
}

// matchedAdminSegment returns the first admin-like segment found in the path.
func matchedAdminSegment(path string) string {
	lower := strings.ToLower(path)
	for _, seg := range adminSegments {
		if strings.Contains(lower, seg) {
			return seg
		}
	}
	return ""
}

// alternativeMethods returns a list of HTTP methods to try when swapping from the given method.
func alternativeMethods(method string) []string {
	switch strings.ToUpper(method) {
	case http.MethodGet:
		return []string{http.MethodPost, http.MethodPut, http.MethodDelete}
	case http.MethodPost:
		return []string{http.MethodGet, http.MethodPut, http.MethodDelete}
	case http.MethodPut:
		return []string{http.MethodGet, http.MethodPost, http.MethodDelete}
	case http.MethodDelete:
		return []string{http.MethodGet, http.MethodPost, http.MethodPut}
	case http.MethodPatch:
		return []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}
	default:
		return []string{http.MethodGet, http.MethodPost}
	}
}

// runMethodSwap tests whether swapping the HTTP method bypasses authorization.
func (m *FunctionAuthModule) runMethodSwap(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	url := strings.TrimRight(target, "/") + tc.Path
	var findings []domain.Finding

	for _, altMethod := range alternativeMethods(tc.Method) {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		resp, err := doRequest(ctx, exec, altMethod, url, tc.Headers, tc.Body, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			endpoint := tc.Method + " " + tc.Path
			findings = append(findings, domain.Finding{
				OWASPId:        "API5:2023",
				ModuleID:       m.ID(),
				Title:          fmt.Sprintf("HTTP Method Swap Bypasses Authorization on %s (tried %s)", endpoint, altMethod),
				Description:    fmt.Sprintf("Swapping the HTTP method from %s to %s on endpoint %s returned HTTP %d without authentication. The server may not enforce method-level authorization.", tc.Method, altMethod, tc.Path, resp.StatusCode),
				Severity:       domain.SeverityHigh,
				CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("%s %s (no auth, swapped from %s)", altMethod, url, tc.Method),
					Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
					Detail: map[string]interface{}{
						"original_method":    tc.Method,
						"alternative_method": altMethod,
						"status_code":        resp.StatusCode,
					},
				},
				Remediation: "Enforce authorization checks for every HTTP method, not just the primary method. Reject unexpected methods with HTTP 405 and verify authorization on all accepted methods.",
				Status:      domain.FindingStatusOpen,
			})
			// One finding per test case is sufficient.
			break
		}
	}

	return findings, nil
}

// runPrivilegeEscalation tests whether a regular user token can access privileged endpoints.
func (m *FunctionAuthModule) runPrivilegeEscalation(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	if auth == nil || auth.Token == "" {
		return nil, nil
	}

	url := strings.TrimRight(target, "/") + tc.Path
	endpoint := tc.Method + " " + tc.Path

	resp, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, auth)
	if err != nil {
		return nil, fmt.Errorf("privilege escalation request failed: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return []domain.Finding{
			{
				OWASPId:        "API5:2023",
				ModuleID:       m.ID(),
				Title:          "Privilege Escalation via Regular User Token on " + endpoint,
				Description:    fmt.Sprintf("Endpoint %s returned HTTP %d when accessed with a regular bearer token. This endpoint may be reserved for higher-privilege roles but is accessible to standard users.", endpoint, resp.StatusCode),
				Severity:       domain.SeverityHigh,
				CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"),
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("%s %s (regular bearer token)", tc.Method, url),
					Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
					Detail: map[string]interface{}{
						"auth_type":   "bearer",
						"status_code": resp.StatusCode,
					},
				},
				Remediation: "Implement role-based access control (RBAC). Validate that the token's role/scope claims authorize access to the requested function before processing the request.",
				Status:      domain.FindingStatusOpen,
			},
		}, nil
	}

	return nil, nil
}
