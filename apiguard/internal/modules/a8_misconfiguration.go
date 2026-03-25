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

// MisconfigModule implements OWASP API8:2023 — Security Misconfiguration.
type MisconfigModule struct{}

func (m *MisconfigModule) ID() string   { return "a8_misconfiguration" }
func (m *MisconfigModule) Name() string { return "Security Misconfiguration" }

// Run executes misconfiguration test cases from the provided suite against the target.
func (m *MisconfigModule) Run(ctx context.Context, exec HTTPExecutor, suite TestSuite, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	// Deduplicate endpoints to avoid redundant requests.
	visited := make(map[string]bool)

	for _, tc := range suite.Cases {
		switch tc.Category {
		case "misconfig_security_headers", "misconfig_debug_info", "misconfig_http_methods":
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
		case "misconfig_security_headers":
			f, err := m.runSecurityHeaders(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)

		case "misconfig_debug_info":
			f, err := m.runDebugInfo(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)

		case "misconfig_http_methods":
			f, err := m.runHTTPMethods(ctx, exec, tc, target, auth)
			if err != nil {
				continue
			}
			findings = append(findings, f...)
		}
	}

	return findings, nil
}

// serverVersionRegexp matches a Server header that includes a version number.
var serverVersionRegexp = regexp.MustCompile(`/\d+\.\d+`)

// runSecurityHeaders sends a GET request and checks the response headers for security issues.
func (m *MisconfigModule) runSecurityHeaders(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	url := strings.TrimRight(target, "/") + tc.Path
	resp, err := doRequest(ctx, exec, http.MethodGet, url, tc.Headers, nil, auth)
	if err != nil {
		return nil, fmt.Errorf("security headers request failed: %w", err)
	}

	headers := resp.Headers

	// --- Missing X-Content-Type-Options ---
	if headers.Get("X-Content-Type-Options") == "" {
		findings = append(findings, domain.Finding{
			OWASPId:        "API8:2023",
			ModuleID:       m.ID(),
			Title:          "Missing X-Content-Type-Options Header",
			Description:    fmt.Sprintf("Endpoint %s %s does not return the X-Content-Type-Options: nosniff header, allowing MIME-type sniffing attacks.", tc.Method, tc.Path),
			Severity:       domain.SeverityMedium,
			CVSSScore:      5.3,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			Status:         domain.FindingStatusOpen,
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("GET %s", url),
				Response: fmt.Sprintf("HTTP %d (X-Content-Type-Options header absent)", resp.StatusCode),
				Detail: map[string]interface{}{
					"missing_header": "X-Content-Type-Options",
				},
			},
			Remediation: "Add the response header: X-Content-Type-Options: nosniff",
		})
	}

	// --- Missing X-Frame-Options or Content-Security-Policy ---
	if headers.Get("X-Frame-Options") == "" && headers.Get("Content-Security-Policy") == "" {
		findings = append(findings, domain.Finding{
			OWASPId:        "API8:2023",
			ModuleID:       m.ID(),
			Title:          "Missing Clickjacking Protection Header",
			Description:    fmt.Sprintf("Endpoint %s %s does not return X-Frame-Options or Content-Security-Policy, leaving it open to clickjacking attacks.", tc.Method, tc.Path),
			Severity:       domain.SeverityMedium,
			CVSSScore:      5.3,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			Status:         domain.FindingStatusOpen,
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("GET %s", url),
				Response: fmt.Sprintf("HTTP %d (X-Frame-Options and Content-Security-Policy headers absent)", resp.StatusCode),
				Detail: map[string]interface{}{
					"missing_headers": []string{"X-Frame-Options", "Content-Security-Policy"},
				},
			},
			Remediation: "Add either X-Frame-Options: DENY or a Content-Security-Policy header with frame-ancestors directive.",
		})
	}

	// --- Server header exposes version info ---
	serverHeader := headers.Get("Server")
	if serverHeader != "" && serverVersionRegexp.MatchString(serverHeader) {
		findings = append(findings, domain.Finding{
			OWASPId:        "API8:2023",
			ModuleID:       m.ID(),
			Title:          "Server Header Exposes Version Information",
			Description:    fmt.Sprintf("Endpoint %s %s returns a Server header that includes version information: %q. This aids targeted attacks against known vulnerabilities.", tc.Method, tc.Path, serverHeader),
			Severity:       domain.SeverityLow,
			CVSSScore:      3.1,
			CVSSVector:     "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
			Status:         domain.FindingStatusOpen,
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("GET %s", url),
				Response: fmt.Sprintf("HTTP %d (Server: %s)", resp.StatusCode, serverHeader),
				Detail: map[string]interface{}{
					"server_header": serverHeader,
				},
			},
			Remediation: "Configure the web server to suppress or genericise the Server response header so that it does not include software version numbers.",
		})
	}

	// --- X-Powered-By header present ---
	poweredBy := headers.Get("X-Powered-By")
	if poweredBy != "" {
		findings = append(findings, domain.Finding{
			OWASPId:        "API8:2023",
			ModuleID:       m.ID(),
			Title:          "X-Powered-By Header Exposes Technology Stack",
			Description:    fmt.Sprintf("Endpoint %s %s returns X-Powered-By: %q, revealing the underlying technology stack to potential attackers.", tc.Method, tc.Path, poweredBy),
			Severity:       domain.SeverityLow,
			CVSSScore:      3.1,
			CVSSVector:     "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
			Status:         domain.FindingStatusOpen,
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("GET %s", url),
				Response: fmt.Sprintf("HTTP %d (X-Powered-By: %s)", resp.StatusCode, poweredBy),
				Detail: map[string]interface{}{
					"x_powered_by": poweredBy,
				},
			},
			Remediation: "Remove or suppress the X-Powered-By response header in your framework/server configuration.",
		})
	}

	// --- Overly permissive CORS on authenticated endpoint ---
	corsOrigin := headers.Get("Access-Control-Allow-Origin")
	if corsOrigin == "*" && auth != nil && auth.Token != "" {
		findings = append(findings, domain.Finding{
			OWASPId:        "API8:2023",
			ModuleID:       m.ID(),
			Title:          "Wildcard CORS on Authenticated Endpoint",
			Description:    fmt.Sprintf("Endpoint %s %s returns Access-Control-Allow-Origin: * on what appears to be an authenticated endpoint. This allows any origin to read the response via cross-site requests.", tc.Method, tc.Path),
			Severity:       domain.SeverityMedium,
			CVSSScore:      5.3,
			CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
			Status:         domain.FindingStatusOpen,
			EndpointPath:   tc.Path,
			EndpointMethod: tc.Method,
			Evidence: domain.Evidence{
				Request:  fmt.Sprintf("GET %s", url),
				Response: fmt.Sprintf("HTTP %d (Access-Control-Allow-Origin: *)", resp.StatusCode),
				Detail: map[string]interface{}{
					"cors_header": corsOrigin,
				},
			},
			Remediation: "Replace the wildcard CORS policy with an explicit allowlist of trusted origins. Never use Access-Control-Allow-Origin: * on endpoints that handle authenticated or sensitive data.",
		})
	}

	return findings, nil
}

// debugInfoPatterns are regular expressions that indicate debug information in a response body.
var debugInfoPatterns = []*regexp.Regexp{
	regexp.MustCompile(`at com\.`),
	regexp.MustCompile(`at java\.`),
	regexp.MustCompile(`Exception`),
	regexp.MustCompile(`Traceback`),
	regexp.MustCompile(`<title>Error</title>`),
	regexp.MustCompile(`(?i)"debug"\s*:`),
}

// runDebugInfo checks whether the response body contains stack traces or debug information.
func (m *MisconfigModule) runDebugInfo(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	url := strings.TrimRight(target, "/") + tc.Path
	resp, err := doRequest(ctx, exec, http.MethodGet, url, tc.Headers, nil, auth)
	if err != nil {
		return nil, fmt.Errorf("debug info request failed: %w", err)
	}

	for _, pat := range debugInfoPatterns {
		if pat.Match(resp.Body) {
			findings = append(findings, domain.Finding{
				OWASPId:        "API8:2023",
				ModuleID:       m.ID(),
				Title:          "Debug Information Leaked in Response",
				Description:    fmt.Sprintf("Endpoint %s %s returns a response containing debug or stack-trace information matching the pattern %q. This can expose application internals to attackers.", tc.Method, tc.Path, pat.String()),
				Severity:       domain.SeverityHigh,
				CVSSScore:      7.5,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
				Status:         domain.FindingStatusOpen,
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("GET %s", url),
					Response: fmt.Sprintf("HTTP %d — body matches pattern %q", resp.StatusCode, pat.String()),
					Detail: map[string]interface{}{
						"pattern": pat.String(),
						"snippet": extractSnippet(resp.Body, pat),
					},
				},
				Remediation: "Disable detailed error messages and stack traces in production. Return generic error responses to clients and log the full detail server-side only.",
			})
			// One finding per endpoint is sufficient.
			break
		}
	}

	return findings, nil
}

// runHTTPMethods sends an OPTIONS request and checks for dangerous allowed methods.
func (m *MisconfigModule) runHTTPMethods(ctx context.Context, exec HTTPExecutor, tc TestCase, target string, auth *AuthConfig) ([]domain.Finding, error) {
	var findings []domain.Finding

	url := strings.TrimRight(target, "/") + tc.Path
	resp, err := doRequest(ctx, exec, http.MethodOptions, url, tc.Headers, nil, auth)
	if err != nil {
		return nil, fmt.Errorf("OPTIONS request failed: %w", err)
	}

	allow := resp.Headers.Get("Allow")
	if allow == "" {
		allow = resp.Headers.Get("Access-Control-Allow-Methods")
	}

	allowUpper := strings.ToUpper(allow)
	for _, dangerous := range []string{"TRACE", "CONNECT"} {
		if strings.Contains(allowUpper, dangerous) {
			findings = append(findings, domain.Finding{
				OWASPId:        "API8:2023",
				ModuleID:       m.ID(),
				Title:          fmt.Sprintf("Dangerous HTTP Method %s Allowed", dangerous),
				Description:    fmt.Sprintf("Endpoint %s %s advertises the %s HTTP method via OPTIONS. This method can be abused for cross-site tracing attacks or tunnelling through proxies.", tc.Method, tc.Path, dangerous),
				Severity:       domain.SeverityMedium,
				CVSSScore:      4.3,
				CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
				Status:         domain.FindingStatusOpen,
				EndpointPath:   tc.Path,
				EndpointMethod: tc.Method,
				Evidence: domain.Evidence{
					Request:  fmt.Sprintf("OPTIONS %s", url),
					Response: fmt.Sprintf("HTTP %d (Allow: %s)", resp.StatusCode, allow),
					Detail: map[string]interface{}{
						"allow_header":    allow,
						"dangerous_method": dangerous,
					},
				},
				Remediation: fmt.Sprintf("Disable the %s HTTP method in your web server and application framework configuration.", dangerous),
			})
		}
	}

	return findings, nil
}

// extractSnippet returns up to 200 bytes surrounding the first match of pat in body.
func extractSnippet(body []byte, pat *regexp.Regexp) string {
	loc := pat.FindIndex(body)
	if loc == nil {
		return ""
	}
	start := loc[0] - 50
	if start < 0 {
		start = 0
	}
	end := loc[1] + 150
	if end > len(body) {
		end = len(body)
	}
	snippet := bytes.TrimSpace(body[start:end])
	return string(snippet)
}
