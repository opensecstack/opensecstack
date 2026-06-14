package checks

import (
	"regexp"
	"strings"
)

// TDS-AUTH check patterns.
var (
	// TDS-AUTH-001: hardcoded API key or secret literal.
	reHardcodedKey = regexp.MustCompile(
		`(?i)(api_key|api_secret|secret)\s*[:=]\s*["'][a-zA-Z0-9]{20,}["']`,
	)

	// TDS-AUTH-002: JWT token stored in a variable named "token" without an
	// expiry check (e.g. exp, expiry, ExpiresAt, expires_in) on a nearby line.
	reJWTToken = regexp.MustCompile(`(?i)\btoken\s*[:=]\s*["'][A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+["']`)

	// TDS-AUTH-003: HTTP Basic auth credentials embedded in a URL.
	reBasicAuthURL = regexp.MustCompile(`https?://[^@\s"']+:[^@\s"']+@`)

	// Helper: anything that looks like an expiry concern on the same line or
	// within ±5 lines.
	reExpiryHint = regexp.MustCompile(`(?i)(exp\b|expir|ExpiresAt|expires_in|exp_time|valid_until)`)
)

// RunAuthChecks inspects each file for authentication-related TDS issues.
func RunAuthChecks(files []ScannedFile) []Finding {
	var findings []Finding

	for _, f := range files {
		for i, line := range f.Lines {
			lineNum := i + 1

			// TDS-AUTH-001 — hardcoded credential literal.
			if loc := reHardcodedKey.FindStringIndex(line); loc != nil {
				findings = append(findings, Finding{
					CheckID:     "TDS-AUTH-001",
					Title:       "Hardcoded API Key or Secret",
					Description: "A credential literal was found directly in source code.",
					Severity:    "critical",
					FilePath:    f.Path,
					Line:        lineNum,
					Column:      loc[0] + 1,
					Snippet:     strings.TrimSpace(line),
					Remediation: "Remove the hardcoded credential and load it from an environment variable or a secrets manager (e.g. Vault, AWS Secrets Manager).",
				})
			}

			// TDS-AUTH-002 — JWT token variable without nearby expiry check.
			if reJWTToken.MatchString(line) {
				// Look ±5 lines for an expiry hint.
				start := i - 5
				if start < 0 {
					start = 0
				}
				end := i + 5
				if end >= len(f.Lines) {
					end = len(f.Lines) - 1
				}
				window := strings.Join(f.Lines[start:end+1], "\n")
				if !reExpiryHint.MatchString(window) {
					findings = append(findings, Finding{
						CheckID:     "TDS-AUTH-002",
						Title:       "JWT Token Without Expiry Check",
						Description: "A JWT token is stored in a variable named 'token' but no expiry validation was found nearby.",
						Severity:    "high",
						FilePath:    f.Path,
						Line:        lineNum,
						Column:      1,
						Snippet:     strings.TrimSpace(line),
						Remediation: "Always validate the 'exp' claim before trusting a JWT. Use a library that enforces expiry (e.g. golang-jwt/jwt, PyJWT).",
					})
				}
			}

			// TDS-AUTH-003 — HTTP Basic auth in URL.
			if loc := reBasicAuthURL.FindStringIndex(line); loc != nil {
				findings = append(findings, Finding{
					CheckID:     "TDS-AUTH-003",
					Title:       "HTTP Basic Auth Credentials in URL",
					Description: "Username and/or password were found embedded directly in a URL.",
					Severity:    "medium",
					FilePath:    f.Path,
					Line:        lineNum,
					Column:      loc[0] + 1,
					Snippet:     strings.TrimSpace(line),
					Remediation: "Pass credentials via the Authorization header instead of embedding them in the URL. URLs are frequently logged and may be stored in browser history.",
				})
			}
		}
	}

	return findings
}
