package customrules

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/opensecstack/apiguard/internal/modules"
)

// CustomRuleModule wraps a CustomRule and implements the modules.Module interface
// so that custom rules run alongside built-in OWASP modules in the scanner pipeline.
type CustomRuleModule struct {
	rule CustomRule
}

// NewModule returns a CustomRuleModule for the given rule.
func NewModule(rule CustomRule) *CustomRuleModule {
	return &CustomRuleModule{rule: rule}
}

// ID implements modules.Module.
func (m *CustomRuleModule) ID() string { return m.rule.ID }

// Name implements modules.Module.
func (m *CustomRuleModule) Name() string { return m.rule.Name }

// Run implements modules.Module. It iterates over the rule's checks, matches
// each check against endpoints in the test suite by Target/Method pattern, executes
// the HTTP request, evaluates the check logic, and collects findings.
func (m *CustomRuleModule) Run(
	ctx context.Context,
	exec modules.HTTPExecutor,
	suite modules.TestSuite,
	target string,
	auth *modules.AuthConfig,
) ([]domain.Finding, error) {
	var findings []domain.Finding

	for _, check := range m.rule.Checks {
		for _, tc := range suite.Cases {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			if !matchesTarget(check.Target, tc.Path) {
				continue
			}
			if !matchesMethod(check.Method, tc.Method) {
				continue
			}

			url := buildEndpointURL(target, tc.Path)
			resp, err := doRequest(ctx, exec, tc.Method, url, tc.Headers, tc.Body, auth)
			if err != nil {
				// A failed HTTP request is not a security finding; skip and continue.
				continue
			}

			finding, triggered := m.evaluate(check, tc, url, resp)
			if triggered {
				findings = append(findings, finding)
				// One finding per (check, endpoint) is sufficient.
				break
			}
		}
	}

	return findings, nil
}

// evaluate applies a single check against a response and returns a finding when the
// check condition is met, plus a boolean indicating whether a finding was raised.
func (m *CustomRuleModule) evaluate(
	check Check,
	tc modules.TestCase,
	requestURL string,
	resp *modules.HTTPResponse,
) (domain.Finding, bool) {
	triggered := false
	detail := map[string]interface{}{
		"check_type": check.Type,
		"endpoint":   tc.Method + " " + tc.Path,
	}

	switch check.Type {

	case "header_missing":
		headerName := check.Params["header"]
		val := resp.Headers.Get(headerName)
		if val == "" {
			triggered = true
			detail["missing_header"] = headerName
		}

	case "header_value":
		headerName := check.Params["header"]
		pattern := check.Params["pattern"]
		val := resp.Headers.Get(headerName)
		matched, err := regexp.MatchString(pattern, val)
		if err != nil || !matched {
			triggered = true
			detail["header"] = headerName
			detail["header_value"] = val
			detail["expected_pattern"] = pattern
		}

	case "status_code":
		expected := parseStatusCodes(check.Params["expected"])
		code := resp.StatusCode
		for _, c := range expected {
			if c == code {
				triggered = true
				break
			}
		}
		detail["status_code"] = code
		detail["expected_codes"] = check.Params["expected"]

	case "response_body_contains":
		text := check.Params["text"]
		if bytes.Contains(resp.Body, []byte(text)) {
			triggered = true
			detail["matched_text"] = text
		}

	case "response_body_not_contains":
		text := check.Params["text"]
		if !bytes.Contains(resp.Body, []byte(text)) {
			triggered = true
			detail["required_text"] = text
		}

	case "response_time_exceeds":
		thresholdMs, _ := strconv.ParseInt(check.Params["ms"], 10, 64)
		actualMs := resp.Duration.Milliseconds()
		if actualMs > thresholdMs {
			triggered = true
			detail["threshold_ms"] = thresholdMs
			detail["actual_ms"] = actualMs
		}
	}

	if !triggered {
		return domain.Finding{}, false
	}

	msg := check.Message
	if msg == "" {
		msg = fmt.Sprintf("Custom rule %s triggered on %s %s", m.rule.ID, tc.Method, tc.Path)
	}

	f := domain.Finding{
		OWASPId:        m.rule.OWASPRef,
		ModuleID:       m.rule.ID,
		Title:          fmt.Sprintf("[%s] %s", m.rule.ID, m.rule.Name),
		Description:    msg,
		Severity:       parseSeverity(m.rule.Severity),
		Status:         domain.FindingStatusOpen,
		EndpointPath:   tc.Path,
		EndpointMethod: tc.Method,
		Remediation:    m.rule.Description,
		Evidence: domain.Evidence{
			Request:  fmt.Sprintf("%s %s", tc.Method, requestURL),
			Response: fmt.Sprintf("HTTP %d (%.0fms)", resp.StatusCode, float64(resp.Duration.Milliseconds())),
			Detail:   detail,
		},
	}

	return f, true
}

// --- helpers ---

// matchesTarget returns true when the check target pattern matches the endpoint path.
// "*" matches everything; otherwise it does a case-insensitive exact path match.
func matchesTarget(pattern, path string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	return strings.EqualFold(pattern, path)
}

// matchesMethod returns true when the check method matches the endpoint method.
// "*" matches all HTTP methods.
func matchesMethod(pattern, method string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	return strings.EqualFold(pattern, method)
}

// buildEndpointURL joins the base target URL with the endpoint path, collapsing
// any duplicate slashes at the boundary.
func buildEndpointURL(target, path string) string {
	return strings.TrimRight(target, "/") + path
}

// parseStatusCodes splits a comma-separated list of status code strings (e.g.
// "401,403") into a slice of integers, silently ignoring malformed entries.
func parseStatusCodes(raw string) []int {
	var codes []int
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if code, err := strconv.Atoi(part); err == nil {
			codes = append(codes, code)
		}
	}
	return codes
}

// parseSeverity normalises a severity string to domain.Severity, defaulting to
// domain.SeverityInfo for unrecognised values.
func parseSeverity(s string) domain.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return domain.SeverityCritical
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	default:
		return domain.SeverityInfo
	}
}

// doRequest builds and dispatches an HTTP request, applying auth credentials.
// It is a lightweight re-implementation kept local to this package so the
// customrules package does not depend on unexported helpers in the modules package.
func doRequest(
	ctx context.Context,
	exec modules.HTTPExecutor,
	method, url string,
	headers map[string]string,
	body []byte,
	auth *modules.AuthConfig,
) (*modules.HTTPResponse, error) {
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

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if auth != nil {
		applyAuth(req, auth)
	}

	return exec.Do(ctx, req)
}

// applyAuth sets authentication headers on req based on the auth config type.
func applyAuth(req *http.Request, auth *modules.AuthConfig) {
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
			default:
				req.Header.Set(auth.APIKeyName, auth.APIKey)
			}
		}
	case "basic":
		if auth.Username != "" {
			req.SetBasicAuth(auth.Username, auth.Password)
		}
	}
}
