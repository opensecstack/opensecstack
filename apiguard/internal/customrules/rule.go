package customrules

// CustomRule defines a user-supplied security check rule loaded from YAML.
type CustomRule struct {
	ID          string  `yaml:"id"`   // e.g. "CR-001"
	Name        string  `yaml:"name"` // Human-readable name
	Description string  `yaml:"description"`
	OWASPRef    string  `yaml:"owasp_ref"` // e.g. "API1:2023" (optional)
	Severity    string  `yaml:"severity"`  // critical|high|medium|low|info
	Enabled     bool    `yaml:"enabled"`   // default true
	Checks      []Check `yaml:"checks"`    // one or more checks to run
}

// Check defines a single condition to evaluate against an HTTP response.
//
// Supported types:
//   - header_missing            – finding if the response is missing the header named in params["header"]
//   - header_value              – finding if response header params["header"] does NOT match params["pattern"] (regex)
//   - status_code               – finding if the response status code IS in params["expected"] (comma-separated list)
//   - response_body_contains    – finding if the response body CONTAINS params["text"] (security leak detection)
//   - response_body_not_contains – finding if the response body does NOT contain params["text"] (required field absent)
//   - response_time_exceeds     – finding if the response time exceeds params["ms"] milliseconds (DoS indicator)
type Check struct {
	// Type is the check category (see list above).
	Type string `yaml:"type"`

	// Target is an endpoint path pattern or "*" for all paths.
	// Simple glob-style matching: "*" matches everything, otherwise the
	// target is compared as a path prefix or exact match.
	Target string `yaml:"target"`

	// Method is the HTTP method to match, or "*" for all methods.
	Method string `yaml:"method"`

	// Params holds type-specific parameters (e.g. {"header": "X-Request-ID"}).
	Params map[string]string `yaml:"params"`

	// Message is the finding message emitted when the check triggers.
	Message string `yaml:"message"`
}

// RuleFile is the top-level structure of a YAML rule file.
// A single file may declare multiple rules under the "rules" key.
type RuleFile struct {
	Rules []CustomRule `yaml:"rules"`
}
