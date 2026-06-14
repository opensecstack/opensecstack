package checks

import (
	"regexp"
	"strings"
)

// TDS-RETRY check patterns.
var (
	// TDS-RETRY-001: direct http.Get / http.Post / client.Do call without a
	// surrounding retry wrapper. We detect the call site; the scanner then
	// checks whether a retry loop is visible in a ±20-line window.
	reHTTPCall = regexp.MustCompile(
		`\bhttp\.(Get|Post|PostForm|Head|Do)\s*\(|\.Do\s*\(req\b`,
	)

	// Indicators that a retry loop exists nearby.
	reRetryHint = regexp.MustCompile(
		`(?i)(retry|backoff|for\s+\w+\s*:?=|for\s+i\s*:?=|for\s+attempt|for\s+{)`,
	)

	// TDS-RETRY-002: fixed sleep multiplied by a literal integer (no jitter).
	reFixedSleep = regexp.MustCompile(`time\.Sleep\s*\([^)]*\*\s*[0-9]`)
)

// RunRetryChecks inspects each file for missing or inadequate retry patterns.
func RunRetryChecks(files []ScannedFile) []Finding {
	var findings []Finding

	for _, f := range files {
		for i, line := range f.Lines {
			lineNum := i + 1
			trimmed := strings.TrimSpace(line)

			// Skip comment lines.
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
				continue
			}

			// TDS-RETRY-001 — HTTP call with no visible retry context.
			if loc := reHTTPCall.FindStringIndex(line); loc != nil {
				start := i - 20
				if start < 0 {
					start = 0
				}
				end := i + 20
				if end >= len(f.Lines) {
					end = len(f.Lines) - 1
				}
				window := strings.Join(f.Lines[start:end+1], "\n")
				if !reRetryHint.MatchString(window) {
					findings = append(findings, Finding{
						CheckID:     "TDS-RETRY-001",
						Title:       "HTTP Call Without Retry Logic",
						Description: "An HTTP call was found without a visible retry/backoff wrapper. Transient errors will cause immediate failures.",
						Severity:    "medium",
						FilePath:    f.Path,
						Line:        lineNum,
						Column:      loc[0] + 1,
						Snippet:     trimmed,
						Remediation: "Wrap HTTP calls with exponential backoff and jitter (e.g. github.com/cenkalti/backoff, tenacity in Python). Retry on 429, 502, 503, 504.",
					})
				}
			}

			// TDS-RETRY-002 — fixed sleep with integer multiplier (no jitter).
			if loc := reFixedSleep.FindStringIndex(line); loc != nil {
				findings = append(findings, Finding{
					CheckID:     "TDS-RETRY-002",
					Title:       "Fixed Sleep Without Jitter in Retry Loop",
					Description: "A retry delay uses a fixed multiplier with no jitter, which can cause a thundering-herd problem.",
					Severity:    "low",
					FilePath:    f.Path,
					Line:        lineNum,
					Column:      loc[0] + 1,
					Snippet:     trimmed,
					Remediation: "Add random jitter to retry sleeps, e.g. time.Sleep(base * time.Duration(attempt) + jitter) where jitter is a random fraction of the base delay.",
				})
			}
		}
	}

	return findings
}
