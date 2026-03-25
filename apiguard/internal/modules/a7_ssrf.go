package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/opensecstack/apiguard/internal/cvss"
	"github.com/opensecstack/apiguard/internal/domain"
)

// SSRFModule implements OWASP API7:2023 — Server Side Request Forgery.
type SSRFModule struct{}

func (m *SSRFModule) ID() string   { return "a7_ssrf" }
func (m *SSRFModule) Name() string { return "Server Side Request Forgery (SSRF)" }

// Run executes SSRF test cases from the provided suite against the target.
func (m *SSRFModule) Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	for _, tc := range suite.Cases {
		if tc.Category != "ssrf_url_param" {
			continue
		}

		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		f, err := m.runSSRFURLParam(ctx, exec, tc, target, auth)
		if err != nil {
			continue
		}
		findings = append(findings, f...)
	}

	return findings, nil
}

// ssrfPayloads are common SSRF probe URLs.
var ssrfPayloads = []string{
	"http://169.254.169.254/latest/meta-data/",
	"http://localhost:80/",
	"http://[::1]:80/",
}

// ssrfURLParamKeywords are parameter name substrings that indicate a URL-like parameter.
var ssrfURLParamKeywords = []string{
	"url", "uri", "redirect", "callback", "webhook",
	"endpoint", "target", "host", "src", "href", "link",
}

// ssrfIndicators are substrings in the response body that indicate SSRF success.
var ssrfIndicators = []string{
	"169.254", "metadata", "localhost", "127.0.0.1",
}

// runSSRFURLParam probes URL-like parameters with SSRF payloads.
func (m *SSRFModule) runSSRFURLParam(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	// Collect URL-like parameter names from the path template.
	urlParams := extractURLParams(tc.Path)

	// If no named params found, default to injecting via a generic "url" query param.
	if len(urlParams) == 0 {
		urlParams = []string{"url"}
	}

	for _, paramName := range urlParams {
		for _, payload := range ssrfPayloads {
			select {
			case <-ctx.Done():
				return findings, ctx.Err()
			default:
			}

			// Build the request URL: replace path param or append as query string.
			reqURL := buildSSRFURL(target, tc.Path, paramName, payload)

			start := time.Now()
			resp, err := doRequest(ctx, exec, tc.Method, reqURL, tc.Headers, tc.Body, auth)
			elapsed := time.Since(start)
			if err != nil {
				// Treat a network timeout/error as a potential indicator (DNS lookup for external host).
				if elapsed > 3*time.Second {
					findings = append(findings, m.newFinding(tc, reqURL, payload, "request timed out — possible DNS/network lookup triggered by SSRF payload"))
				}
				continue
			}

			indicator := detectSSRFResponse(resp, elapsed)
			if indicator != "" {
				findings = append(findings, m.newFinding(tc, reqURL, payload, indicator))
				// One confirmed finding per parameter is sufficient.
				break
			}
		}
	}

	return findings, nil
}

// extractURLParams returns parameter names from the path template that look like URL parameters.
func extractURLParams(pathTemplate string) []string {
	var params []string
	// Check path segments for {param} placeholders with URL-like names.
	segments := strings.Split(pathTemplate, "/")
	for _, seg := range segments {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			name := strings.ToLower(seg[1 : len(seg)-1])
			for _, kw := range ssrfURLParamKeywords {
				if strings.Contains(name, kw) {
					params = append(params, name)
					break
				}
			}
		}
	}
	// Also check query-string-style parameter names embedded in the path (e.g. ?url=).
	if idx := strings.Index(pathTemplate, "?"); idx != -1 {
		queryPart := pathTemplate[idx+1:]
		for _, part := range strings.Split(queryPart, "&") {
			kv := strings.SplitN(part, "=", 2)
			name := strings.ToLower(kv[0])
			for _, kw := range ssrfURLParamKeywords {
				if strings.Contains(name, kw) {
					params = append(params, name)
					break
				}
			}
		}
	}
	return params
}

// buildSSRFURL injects the payload into the appropriate parameter position.
func buildSSRFURL(target, pathTemplate, paramName, payload string) string {
	// If the path has a {paramName} placeholder, replace it directly.
	placeholder := "{" + paramName + "}"
	if strings.Contains(pathTemplate, placeholder) {
		replaced := strings.ReplaceAll(pathTemplate, placeholder, payload)
		return strings.TrimRight(target, "/") + replaced
	}

	// Otherwise append as a query parameter.
	base := strings.TrimRight(target, "/") + pathTemplate
	if strings.Contains(base, "?") {
		return base + "&" + paramName + "=" + payload
	}
	return base + "?" + paramName + "=" + payload
}

// detectSSRFResponse checks a response for SSRF indicators and returns a description if found.
func detectSSRFResponse(resp *HTTPResponse, elapsed time.Duration) string {
	body := strings.ToLower(string(resp.Body))

	for _, ind := range ssrfIndicators {
		if strings.Contains(body, ind) {
			return fmt.Sprintf("response body contains SSRF indicator %q", ind)
		}
	}

	if resp.StatusCode == http.StatusOK && len(resp.Body) > 100 {
		return "server returned HTTP 200 with non-trivial body — may have fetched the SSRF payload URL"
	}

	if elapsed > 3*time.Second {
		return fmt.Sprintf("response took %s — possible DNS lookup or network fetch triggered by SSRF payload", elapsed.Round(time.Millisecond))
	}

	return ""
}

// newFinding constructs a HIGH SSRF finding.
func (m *SSRFModule) newFinding(tc TestCase, reqURL, payload, indicator string) domain.Finding {
	return domain.Finding{
		OWASPId:        "API7:2023",
		ModuleID:       m.ID(),
		Title:          "Server Side Request Forgery (SSRF)",
		Description:    fmt.Sprintf("Endpoint %s %s appears vulnerable to SSRF. Injecting the payload %q triggered: %s", tc.Method, tc.Path, payload, indicator),
		Severity:       domain.SeverityHigh,
		CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
		CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
		Status:         domain.FindingStatusOpen,
		EndpointPath:   tc.Path,
		EndpointMethod: tc.Method,
		Evidence: domain.Evidence{
			Request:  fmt.Sprintf("%s %s", tc.Method, reqURL),
			Response: indicator,
			Detail: map[string]interface{}{
				"payload":   payload,
				"indicator": indicator,
			},
		},
		Remediation: "Validate and restrict URLs supplied by clients. Use an allowlist of permitted schemes, hosts, and ports. Block access to internal/cloud-metadata addresses (169.254.169.254, localhost, etc.) at the network layer. Never forward user-controlled URLs without sanitisation.",
	}
}
