package modules

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/opensecstack/apiguard/internal/domain"
)

// BOLAModule implements OWASP API1:2023 — Broken Object Level Authorization.
type BOLAModule struct{}

func (m *BOLAModule) ID() string   { return "a1_bola" }
func (m *BOLAModule) Name() string { return "Broken Object Level Authorization (BOLA)" }

// Run executes BOLA test cases from the provided suite against the target.
func (m *BOLAModule) Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	for _, tc := range suite.Cases {
		if tc.Category != "bola_id_enum" && tc.Category != "bola_cross_user" {
			continue
		}

		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		switch tc.Category {
		case "bola_id_enum":
			f, err := m.runIDEnumeration(ctx, exec, tc, target, auth)
			if err != nil {
				// Log but continue — one failing test should not abort the whole module.
				continue
			}
			findings = append(findings, f...)
		case "bola_cross_user":
			f, err := m.runCrossUser(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

// runIDEnumeration tests whether sequential or predictable IDs are accepted
// for resources that should require object-level authorization.
func (m *BOLAModule) runIDEnumeration(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	// Try a set of predictable IDs to see if the server returns 200 without proper authz.
	testIDs := generateTestIDs(tc.Path)

	// Baseline: request with auth to establish the expected authorized response.
	baselineResp, err := doRequest(ctx, exec, tc.Method, resolveFirstID(target, tc.Path, testIDs), tc.Headers, tc.Body, auth)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	// If baseline itself returns 401/403, skip (endpoint is protected as expected).
	if baselineResp.StatusCode == http.StatusUnauthorized || baselineResp.StatusCode == http.StatusForbidden {
		return nil, nil
	}

	// Try IDs that definitely don't belong to the authenticated user.
	for _, testID := range testIDs[1:] {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		url := buildURL(target, tc.Path, testID)
		resp, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, auth)
		if err != nil {
			continue
		}

		// BOLA finding: server returns 200 for an ID that likely belongs to another user.
		if resp.StatusCode == http.StatusOK {
			findings = append(findings, domain.Finding{
				OWASPId:        "API1:2023",
				ModuleID:       m.ID(),
				Title:          "Broken Object Level Authorization — ID Enumeration",
				Description:    fmt.Sprintf("Endpoint %s %s returned HTTP 200 for object ID %q without apparent object-level authorization check. An attacker may enumerate IDs to access arbitrary objects.", tc.Method, tc.Path, testID),
				Severity:       domain.SeverityCritical,
				Status:         domain.FindingStatusOpen,
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("%s %s", tc.Method, url),
					Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
					Detail: map[string]interface{}{
						"test_id":                testID,
						"notes":                  "Object returned without authorization check on resource ID",
					},
				},
				Remediation: "Implement object-level authorization checks. Verify that the authenticated user owns or has explicit access to the requested resource ID before returning it.",
			})
			// One confirmed finding per path is sufficient.
			break
		}
	}

	return findings, nil
}

// runCrossUser tests whether a token belonging to user A can access resources of user B.
func (m *BOLAModule) runCrossUser(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	if auth == nil || len(auth.OtherTokens) == 0 {
		// Cannot run cross-user test without a second token — skip, not an error.
		return nil, nil
	}

	var findings []domain.Finding

	// Step 1: Establish a resource URL using user A's token.
	testIDs := generateTestIDs(tc.Path)
	if len(testIDs) == 0 {
		return nil, nil
	}

	url := buildURL(target, tc.Path, testIDs[0])

	// Step 2: Access the same resource using user B's token.
	for _, otherToken := range auth.OtherTokens {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		altAuth := &AuthConfig{
			Type:  auth.Type,
			Token: otherToken,
		}
		resp, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, altAuth)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			findings = append(findings, domain.Finding{
				OWASPId:        "API1:2023",
				ModuleID:       m.ID(),
				Title:          "Broken Object Level Authorization — Cross-User Access",
				Description:    fmt.Sprintf("Endpoint %s %s returned HTTP 200 when accessed with a different user's token. User B can access resources belonging to User A.", tc.Method, tc.Path),
				Severity:       domain.SeverityCritical,
				Status:         domain.FindingStatusOpen,
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("%s %s (with alternate user token)", tc.Method, url),
					Response: fmt.Sprintf("HTTP %d", resp.StatusCode),
					Detail: map[string]interface{}{
						"notes": "Resource accessible by a different authenticated user",
					},
				},
				Remediation: "Enforce per-object ownership checks. Use the authenticated user's identity (from the token) to validate access to each object, not just route-level authorization.",
			})
			break
		}
	}

	return findings, nil
}

// --- helpers ---

var numericIDPattern = regexp.MustCompile(`\{[^}]+\}`)

// generateTestIDs extracts the path template and returns a set of test IDs to probe.
func generateTestIDs(pathTemplate string) []string {
	if !numericIDPattern.MatchString(pathTemplate) {
		return nil
	}
	// Use a mix of sequential integers and common values for broad coverage.
	return []string{"1", "2", "3", "100", "9999", "0", "-1"}
}

// resolveFirstID returns the URL with the first test ID substituted.
func resolveFirstID(target, pathTemplate string, ids []string) string {
	if len(ids) == 0 {
		return target + pathTemplate
	}
	return buildURL(target, pathTemplate, ids[0])
}

// buildURL substitutes the first path parameter with id and prepends target.
func buildURL(target, pathTemplate, id string) string {
	replaced := numericIDPattern.ReplaceAllStringFunc(pathTemplate, func(s string) string {
		return id
	})
	return strings.TrimRight(target, "/") + replaced
}

// doRequest builds and executes an HTTP request applying auth headers.
func doRequest(ctx context.Context, exec HTTPExecutor, method, url string, headers map[string]string, body []byte, auth *AuthConfig) (*HTTPResponse, error) {
	var bodyReader *bytes.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	// Apply headers from the test case.
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Apply authentication.
	if auth != nil {
		applyAuth(req, auth)
	}

	return exec.Do(ctx, req)
}

// applyAuth sets the appropriate authentication headers on req.
func applyAuth(req *http.Request, auth *AuthConfig) {
	switch strings.ToLower(auth.Type) {
	case "bearer", "jwt", "oauth2":
		if auth.Token != "" {
			req.Header.Set("Authorization", "Bearer "+auth.Token)
		}
	case "apikey":
		if auth.APIKey != "" {
			switch strings.ToLower(auth.APIKeyIn) {
			case "query":
				q := req.URL.Query()
				q.Set(auth.APIKeyName, auth.APIKey)
				req.URL.RawQuery = q.Encode()
			default: // header
				req.Header.Set(auth.APIKeyName, auth.APIKey)
			}
		}
	case "basic":
		if auth.Username != "" {
			req.SetBasicAuth(auth.Username, auth.Password)
		}
	}
}

