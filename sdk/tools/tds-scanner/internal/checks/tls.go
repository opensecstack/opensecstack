package checks

import (
	"regexp"
	"strings"
)

// TDS-TLS check patterns.
var (
	// TDS-TLS-001: TLS verification explicitly disabled.
	reTLSSkipVerify = regexp.MustCompile(
		`(?i)(InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|danger_accept_invalid_certs\s*=\s*true)`,
	)

	// TDS-TLS-002: plain HTTP base URL passed to a client constructor.
	// We look for http:// (not https://) assigned to a variable or passed as an
	// argument, avoiding false positives from comments.
	reHTTPBaseURL = regexp.MustCompile(`["']http://[a-zA-Z0-9]`)

	// TDS-TLS-003: Python SSLContext with CERT_NONE (verification disabled).
	reSSLContextNone = regexp.MustCompile(`(?i)ssl\.CERT_NONE|ssl_context\.check_hostname\s*=\s*False`)
)

// RunTLSChecks inspects each file for TLS-related TDS issues.
func RunTLSChecks(files []ScannedFile) []Finding {
	var findings []Finding

	for _, f := range files {
		for i, line := range f.Lines {
			lineNum := i + 1
			trimmed := strings.TrimSpace(line)

			// Skip pure comment lines (best-effort for common styles).
			if strings.HasPrefix(trimmed, "//") ||
				strings.HasPrefix(trimmed, "#") ||
				strings.HasPrefix(trimmed, "*") {
				continue
			}

			// TDS-TLS-001 — InsecureSkipVerify / verify=False.
			if loc := reTLSSkipVerify.FindStringIndex(line); loc != nil {
				findings = append(findings, Finding{
					CheckID:     "TDS-TLS-001",
					Title:       "TLS Verification Disabled",
					Description: "TLS certificate verification is explicitly disabled, making the connection vulnerable to man-in-the-middle attacks.",
					Severity:    "critical",
					FilePath:    f.Path,
					Line:        lineNum,
					Column:      loc[0] + 1,
					Snippet:     trimmed,
					Remediation: "Remove InsecureSkipVerify/verify=False or set it to the secure default (true/True). If you need to trust a private CA, load its certificate instead.",
				})
			}

			// TDS-TLS-002 — HTTP (not HTTPS) base URL.
			if loc := reHTTPBaseURL.FindStringIndex(line); loc != nil {
				findings = append(findings, Finding{
					CheckID:     "TDS-TLS-002",
					Title:       "Plaintext HTTP Base URL",
					Description: "An HTTP (not HTTPS) URL is used as a client base URL, transmitting data without encryption.",
					Severity:    "high",
					FilePath:    f.Path,
					Line:        lineNum,
					Column:      loc[0] + 1,
					Snippet:     trimmed,
					Remediation: "Change the scheme to https:// and ensure the target server has a valid TLS certificate.",
				})
			}

			// TDS-TLS-003 — Python SSLContext with verification disabled.
			if loc := reSSLContextNone.FindStringIndex(line); loc != nil {
				findings = append(findings, Finding{
					CheckID:     "TDS-TLS-003",
					Title:       "Python SSLContext With Disabled Verification",
					Description: "An SSL context has certificate or hostname verification disabled.",
					Severity:    "medium",
					FilePath:    f.Path,
					Line:        lineNum,
					Column:      loc[0] + 1,
					Snippet:     trimmed,
					Remediation: "Use ssl.create_default_context() and do not set check_hostname=False or verify_mode=ssl.CERT_NONE.",
				})
			}
		}
	}

	return findings
}
