package checks

import (
	"regexp"
	"strings"
)

// TDS-HDR check patterns.
var (
	// Markers that indicate HTTP client creation or request construction.
	reClientNew = regexp.MustCompile(
		`(?i)(http\.Client\s*\{|requests\.(get|post|put|patch|delete|head|session)|new_client|NewClient|Client::new|reqwest::Client)`,
	)

	// X-Request-ID header being set anywhere in the file.
	reXRequestID = regexp.MustCompile(`(?i)X-Request-ID|x_request_id|XRequestID`)

	// User-Agent header being set anywhere in the file. Matches both
	// declaration/literal styles ("User-Agent": ..., User-Agent = ...) and
	// call styles (req.Header.Set("User-Agent", ...)), mirroring how
	// reXRequestID matches X-Request-ID regardless of calling convention.
	reUserAgent = regexp.MustCompile(`(?i)(User-Agent|user_agent|UserAgent)`)
)

// RunHeaderChecks inspects each file for missing security/correlation headers
// in HTTP client setup code.
func RunHeaderChecks(files []ScannedFile) []Finding {
	var findings []Finding

	for _, f := range files {
		content := string(f.Content)

		// Only bother if the file appears to construct an HTTP client.
		hasClient := reClientNew.MatchString(content)
		if !hasClient {
			continue
		}

		// TDS-HDR-001 — no X-Request-ID correlation header anywhere in the file.
		if !reXRequestID.MatchString(content) {
			// Report at the first client-construction line.
			for i, line := range f.Lines {
				if reClientNew.MatchString(line) {
					findings = append(findings, Finding{
						CheckID:     "TDS-HDR-001",
						Title:       "Missing X-Request-ID Correlation Header",
						Description: "The HTTP client does not appear to set an X-Request-ID header, making distributed tracing and log correlation difficult.",
						Severity:    "medium",
						FilePath:    f.Path,
						Line:        i + 1,
						Column:      1,
						Snippet:     strings.TrimSpace(line),
						Remediation: "Generate a UUID per request and set it as the X-Request-ID header. Propagate it to downstream services and include it in logs.",
					})
					break
				}
			}
		}

		// TDS-HDR-002 — no User-Agent set on the HTTP client.
		if !reUserAgent.MatchString(content) {
			for i, line := range f.Lines {
				if reClientNew.MatchString(line) {
					findings = append(findings, Finding{
						CheckID:     "TDS-HDR-002",
						Title:       "No User-Agent Set on HTTP Client",
						Description: "The HTTP client does not set a User-Agent header. Servers may reject or throttle requests without a recognisable agent string.",
						Severity:    "low",
						FilePath:    f.Path,
						Line:        i + 1,
						Column:      1,
						Snippet:     strings.TrimSpace(line),
						Remediation: "Set a descriptive User-Agent header that includes your application name and version, e.g. \"opensecstack-sdk/1.0\".",
					})
					break
				}
			}
		}
	}

	return findings
}
