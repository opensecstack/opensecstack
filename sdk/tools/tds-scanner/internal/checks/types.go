package checks

// ScannedFile holds the content of a single source file together with its
// already-split lines (for quick line-number lookup).
type ScannedFile struct {
	Path    string
	Content []byte
	Lines   []string
}

// Finding represents a single TDS compliance issue discovered in source code.
type Finding struct {
	CheckID     string // e.g. "TDS-AUTH-001"
	Title       string
	Description string
	Severity    string // "critical" | "high" | "medium" | "low" | "info"
	FilePath    string
	Line        int
	Column      int
	Snippet     string // the problematic source line
	Remediation string
}

// SeverityRank returns a numeric rank for a severity string so that findings
// can be sorted (higher number = more severe).
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
