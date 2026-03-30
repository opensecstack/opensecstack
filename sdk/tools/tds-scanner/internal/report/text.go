package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/opensecstack/tds-scanner/internal/checks"
)

// severityLabel maps severity strings to their coloured/bracketed label.
func severityLabel(s string) string {
	return "[" + strings.ToUpper(s) + "]"
}

// WriteText writes a human-readable text/table report to w.
func WriteText(
	w io.Writer,
	target string,
	language string,
	checksRun int,
	findings []checks.Finding,
	minSeverity string,
	result string,
) error {
	// Header
	fmt.Fprintln(w, "TDS Scanner Results")
	fmt.Fprintln(w, "===================")
	fmt.Fprintf(w, "Target:   %s\n", target)
	fmt.Fprintf(w, "Language: %s\n", language)
	fmt.Fprintf(w, "Checks:   %d checks run\n", checksRun)
	fmt.Fprintln(w)

	// Findings
	fmt.Fprintf(w, "FINDINGS (%d total)\n", len(findings))
	fmt.Fprintln(w, strings.Repeat("─", 50))

	if len(findings) == 0 {
		fmt.Fprintln(w, "  No findings at or above the", strings.ToUpper(minSeverity), "threshold.")
	}

	for _, f := range findings {
		fmt.Fprintf(w, "\n%s %s — %s\n", severityLabel(f.Severity), f.CheckID, f.Title)
		fmt.Fprintf(w, "  File: %s:%d\n", f.FilePath, f.Line)
		if f.Snippet != "" {
			fmt.Fprintf(w, "  Code: %s\n", f.Snippet)
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "  Fix:  %s\n", f.Remediation)
		}
	}

	// Summary
	counts := summaryCounts(findings)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "SUMMARY")
	fmt.Fprintln(w, strings.Repeat("─", 50))
	fmt.Fprintf(w, "  Critical: %-3d  High: %-3d  Medium: %-3d  Low: %-3d  Info: %d\n",
		counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"])

	resultLabel := strings.ToUpper(result)
	if result == "pass" {
		fmt.Fprintf(w, "  Result: %s\n", resultLabel)
	} else {
		fmt.Fprintf(w, "  Result: %s (findings at or above %s threshold)\n",
			resultLabel, strings.ToUpper(minSeverity))
	}

	return nil
}

// summaryCounts tallies findings by severity.
func summaryCounts(findings []checks.Finding) map[string]int {
	m := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, f := range findings {
		if _, ok := m[f.Severity]; ok {
			m[f.Severity]++
		}
	}
	return m
}
