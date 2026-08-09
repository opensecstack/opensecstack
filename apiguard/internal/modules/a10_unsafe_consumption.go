package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/opensecstack/apiguard/internal/cvss"
	"github.com/opensecstack/apiguard/internal/domain"
)

// UnsafeConsumptionModule implements OWASP API10:2023 — Unsafe Consumption of APIs.
type UnsafeConsumptionModule struct{}

func (m *UnsafeConsumptionModule) ID() string   { return "a10_unsafe_consumption" }
func (m *UnsafeConsumptionModule) Name() string { return "Unsafe Consumption of APIs" }

// Run executes unsafe-consumption test cases from the provided suite against the target.
func (m *UnsafeConsumptionModule) Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	visited := make(map[string]bool)

	for _, tc := range suite.Cases {
		switch tc.Category {
		case "unsafe_redirect", "unsafe_content_type", "unsafe_third_party_data":
		default:
			continue
		}

		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		key := tc.Category + "|" + tc.Method + "|" + tc.Path
		if visited[key] {
			continue
		}
		visited[key] = true

		switch tc.Category {
		case "unsafe_redirect":
			f, err := m.runOpenRedirect(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)

		case "unsafe_content_type":
			f, err := m.runContentTypeMismatch(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)

		case "unsafe_third_party_data":
			f, err := m.runThirdPartyData(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

// runOpenRedirect sends a request without following redirects and checks whether any 3xx
// Location header points to a different host than the target.
func (m *UnsafeConsumptionModule) runOpenRedirect(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	reqURL := strings.TrimRight(target, "/") + tc.Path
	// The DefaultExecutor already does not follow redirects (http.ErrUseLastResponse).
	resp, err := doRequest(ctx, exec, tc.Method, reqURL, tc.Headers, tc.Body, auth)
	if err != nil {
		return nil, fmt.Errorf("open redirect request failed: %w", err)
	}

	// Only check redirect responses.
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return nil, nil
	}

	location := resp.Headers.Get("Location")
	if location == "" {
		return nil, nil
	}

	// Parse the Location header to determine its host.
	locationURL, err := url.Parse(location)
	if err != nil || locationURL.Host == "" {
		// Relative redirect — same host, not an open redirect.
		return nil, nil
	}

	// Parse the target to get its host.
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}

	// Compare hosts (strip port for a fair comparison).
	targetHost := strings.ToLower(stripPort(targetURL.Host))
	locationHost := strings.ToLower(stripPort(locationURL.Host))

	if locationHost != targetHost {
		findings = append(findings, domain.Finding{
			OWASPId:        "API10:2023",
			ModuleID:       m.ID(),
			Title:          "Open Redirect to External Domain",
			Description:    fmt.Sprintf("Endpoint %s %s returned HTTP %d with a Location header pointing to an external domain %q (target host: %q). An attacker can exploit this to redirect users to malicious sites.", tc.Method, tc.Path, resp.StatusCode, locationHost, targetHost),
			Severity:       domain.SeverityHigh,
			CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"),
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
			Status:         domain.FindingStatusOpen,
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s", tc.Method, reqURL),
				Response: fmt.Sprintf("HTTP %d (Location: %s)", resp.StatusCode, location),
				Detail: map[string]interface{}{
					"status_code":   resp.StatusCode,
					"location":      location,
					"location_host": locationHost,
					"target_host":   targetHost,
				},
			},
			Remediation: "Validate all redirect destinations against an explicit allowlist of permitted hosts. Never redirect to user-controlled or third-party URLs without validation.",
		})
	}

	return findings, nil
}

// runContentTypeMismatch sends a request with Accept: application/json and checks whether
// the response Content-Type matches.
func (m *UnsafeConsumptionModule) runContentTypeMismatch(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	reqURL := strings.TrimRight(target, "/") + tc.Path

	// Merge the test case headers with the JSON Accept header.
	headers := make(map[string]string)
	for k, v := range tc.Headers {
		headers[k] = v
	}
	headers["Accept"] = "application/json"

	resp, err := doRequest(ctx, exec, tc.Method, reqURL, headers, tc.Body, auth)
	if err != nil {
		return nil, fmt.Errorf("content-type mismatch request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	contentType := resp.Headers.Get("Content-Type")
	if contentType == "" {
		findings = append(findings, domain.Finding{
			OWASPId:        "API10:2023",
			ModuleID:       m.ID(),
			Title:          "Missing Content-Type Header in Response",
			Description:    fmt.Sprintf("Endpoint %s %s returned HTTP 200 with no Content-Type header, despite the request specifying Accept: application/json. This can cause clients to misinterpret the response.", tc.Method, tc.Path),
			Severity:       domain.SeverityMedium,
			CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
			Status:         domain.FindingStatusOpen,
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s (Accept: application/json)", tc.Method, reqURL),
				Response: fmt.Sprintf("HTTP %d (Content-Type: <absent>)", resp.StatusCode),
				Detail: map[string]interface{}{
					"accept_header":       "application/json",
					"content_type_header": "",
				},
			},
			Remediation: "Always set an explicit Content-Type header on API responses. Ensure content negotiation is handled correctly server-side.",
		})
		return findings, nil
	}

	if !strings.Contains(strings.ToLower(contentType), "json") {
		findings = append(findings, domain.Finding{
			OWASPId:        "API10:2023",
			ModuleID:       m.ID(),
			Title:          "Content-Type Mismatch in API Response",
			Description:    fmt.Sprintf("Endpoint %s %s returned HTTP 200 with Content-Type %q, but the request specified Accept: application/json. This mismatch may indicate improper content negotiation or that the server is returning unexpected data formats.", tc.Method, tc.Path, contentType),
			Severity:       domain.SeverityMedium,
			CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
			Status:         domain.FindingStatusOpen,
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s (Accept: application/json)", tc.Method, reqURL),
				Response: fmt.Sprintf("HTTP %d (Content-Type: %s)", resp.StatusCode, contentType),
				Detail: map[string]interface{}{
					"accept_header":       "application/json",
					"content_type_header": contentType,
				},
			},
			Remediation: "Implement proper content negotiation. Return the content type that matches the Accept header, and validate that API consumers receive responses in the expected format.",
		})
	}

	return findings, nil
}

// urlPattern matches HTTP/HTTPS URLs in a response body.
var urlPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// runThirdPartyData parses the response body for URLs that differ from the target host.
func (m *UnsafeConsumptionModule) runThirdPartyData(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	reqURL := strings.TrimRight(target, "/") + tc.Path
	resp, err := doRequest(ctx, exec, tc.Method, reqURL, tc.Headers, tc.Body, auth)
	if err != nil {
		return nil, fmt.Errorf("third-party data request failed: %w", err)
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target URL: %w", err)
	}
	targetHost := strings.ToLower(stripPort(targetURL.Host))

	matches := urlPattern.FindAll(resp.Body, -1)
	thirdPartyURLs := make(map[string]struct{})

	for _, match := range matches {
		parsed, parseErr := url.Parse(string(match))
		if parseErr != nil {
			continue
		}
		host := strings.ToLower(stripPort(parsed.Host))
		if host != "" && host != targetHost {
			thirdPartyURLs[host] = struct{}{}
		}
	}

	if len(thirdPartyURLs) > 0 {
		domains := make([]string, 0, len(thirdPartyURLs))
		for d := range thirdPartyURLs {
			domains = append(domains, d)
		}

		findings = append(findings, domain.Finding{
			OWASPId:        "API10:2023",
			ModuleID:       m.ID(),
			Title:          "Third-Party Domain URLs in API Response",
			Description:    fmt.Sprintf("Endpoint %s %s returned a response body containing URLs from third-party domains: %s. If this data originates from an upstream API, it may not be validated before being forwarded to clients.", tc.Method, tc.Path, strings.Join(domains, ", ")),
			Severity:       domain.SeverityInfo,
			CVSSScore:      cvss.MustScore("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
			CVSSVector:     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
			Status:         domain.FindingStatusOpen,
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("%s %s", tc.Method, reqURL),
				Response: fmt.Sprintf("HTTP %d — body contains URLs from: %s", resp.StatusCode, strings.Join(domains, ", ")),
				Detail: map[string]interface{}{
					"third_party_domains": domains,
					"target_host":         targetHost,
				},
			},
			Remediation: "Validate and sanitise all data received from third-party APIs before including it in responses. Implement an allowlist of trusted upstream sources and reject unexpected content.",
		})
	}

	return findings, nil
}

// stripPort removes the port component from a host string.
func stripPort(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Confirm it is a port (not an IPv6 address without brackets).
		if !strings.Contains(host, "[") {
			return host[:idx]
		}
	}
	return host
}
