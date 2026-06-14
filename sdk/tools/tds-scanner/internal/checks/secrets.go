package checks

import (
	"regexp"
	"strings"
)

// TDS-SECRET check patterns.
var (
	// TDS-SECRET-001: hardcoded value assigned to an env-var-like variable.
	// Matches patterns such as: PASSWORD = "abc123secret", DB_PASSWORD: "..."
	reHardcodedEnvSecret = regexp.MustCompile(
		`(?i)(password|passwd|pwd|secret|token|auth_key|private_key)\s*[:=]\s*["'][^"']{8,}["']`,
	)

	// TDS-SECRET-002: PEM-encoded private key header in source.
	rePrivateKeyPEM = regexp.MustCompile(
		`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
	)

	// TDS-SECRET-003: password embedded in a connection/DSN string.
	reConnStringPassword = regexp.MustCompile(`://[^:@\s"']+:[^@\s"']{8,}@`)
)

// RunSecretChecks inspects each file for leaked or hardcoded secrets.
func RunSecretChecks(files []ScannedFile) []Finding {
	var findings []Finding

	for _, f := range files {
		for i, line := range f.Lines {
			lineNum := i + 1
			trimmed := strings.TrimSpace(line)

			// Skip pure comment lines.
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
				continue
			}

			// TDS-SECRET-001 — hardcoded credential in an env-var-style assignment.
			if loc := reHardcodedEnvSecret.FindStringIndex(line); loc != nil {
				findings = append(findings, Finding{
					CheckID:     "TDS-SECRET-001",
					Title:       "Potential Hardcoded Secret in Environment Variable Assignment",
					Description: "A variable whose name suggests a secret contains a hardcoded string literal.",
					Severity:    "critical",
					FilePath:    f.Path,
					Line:        lineNum,
					Column:      loc[0] + 1,
					Snippet:     trimmed,
					Remediation: "Load secrets at runtime from environment variables (os.Getenv) or a secrets manager. Never commit credential values to source control.",
				})
			}

			// TDS-SECRET-002 — PEM private key material.
			if loc := rePrivateKeyPEM.FindStringIndex(line); loc != nil {
				findings = append(findings, Finding{
					CheckID:     "TDS-SECRET-002",
					Title:       "Private Key in Source File",
					Description: "A PEM private key header was found, indicating key material may be embedded in source code.",
					Severity:    "high",
					FilePath:    f.Path,
					Line:        lineNum,
					Column:      loc[0] + 1,
					Snippet:     trimmed,
					Remediation: "Remove the private key from the repository immediately. Rotate the key, load it from a secure vault or mounted secret, and add *.pem / *.key to .gitignore.",
				})
			}

			// TDS-SECRET-003 — password in connection string.
			if loc := reConnStringPassword.FindStringIndex(line); loc != nil {
				findings = append(findings, Finding{
					CheckID:     "TDS-SECRET-003",
					Title:       "Password in Connection String",
					Description: "A connection string (database, AMQP, Redis, etc.) contains an inline password.",
					Severity:    "medium",
					FilePath:    f.Path,
					Line:        lineNum,
					Column:      loc[0] + 1,
					Snippet:     trimmed,
					Remediation: "Move the password out of the connection string into a separate secret and construct the DSN at runtime, or use environment variable expansion supported by the driver.",
				})
			}
		}
	}

	return findings
}
