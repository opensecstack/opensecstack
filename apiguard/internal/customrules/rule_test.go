package customrules

import (
	"testing"

	"github.com/opensecstack/apiguard/internal/domain"
)

// ---------------------------------------------------------------------------
// CustomRule struct fields
// ---------------------------------------------------------------------------

// TestCustomRule_Fields verifies that all exported fields on CustomRule are
// assignable and readable without modification.
func TestCustomRule_Fields(t *testing.T) {
	r := CustomRule{
		ID:          "CR-042",
		Name:        "Probe Rule",
		Description: "A rule for testing",
		OWASPRef:    "API3:2023",
		Severity:    "high",
		Enabled:     true,
		Checks: []Check{
			{
				Type:    "header_missing",
				Target:  "/api/v1/scans",
				Method:  "GET",
				Message: "Missing X-Request-ID",
				Params:  map[string]string{"header": "X-Request-ID"},
			},
		},
	}

	if r.ID != "CR-042" {
		t.Errorf("ID = %q, want CR-042", r.ID)
	}
	if r.Name != "Probe Rule" {
		t.Errorf("Name = %q, want 'Probe Rule'", r.Name)
	}
	if r.OWASPRef != "API3:2023" {
		t.Errorf("OWASPRef = %q, want 'API3:2023'", r.OWASPRef)
	}
	if r.Severity != "high" {
		t.Errorf("Severity = %q, want 'high'", r.Severity)
	}
	if !r.Enabled {
		t.Error("Enabled = false, want true")
	}
	if len(r.Checks) != 1 {
		t.Fatalf("len(Checks) = %d, want 1", len(r.Checks))
	}
	if r.Checks[0].Type != "header_missing" {
		t.Errorf("Checks[0].Type = %q, want 'header_missing'", r.Checks[0].Type)
	}
}

// TestCustomRule_EmptyIDIsPermitted verifies that a CustomRule with no ID can
// be constructed (validation is a separate concern handled by Validate).
func TestCustomRule_EmptyIDIsPermitted(t *testing.T) {
	r := CustomRule{Name: "No ID Rule", Severity: "low", Enabled: true}
	if r.ID != "" {
		t.Errorf("ID = %q, want empty string for zero value", r.ID)
	}
}

// ---------------------------------------------------------------------------
// matchesTarget (path pattern matching)
// ---------------------------------------------------------------------------

func TestMatchesTarget_WildcardMatchesAnything(t *testing.T) {
	paths := []string{"/", "/api/v1/scans", "/anything/at/all", ""}
	for _, path := range paths {
		if !matchesTarget("*", path) {
			t.Errorf("matchesTarget('*', %q) = false, want true", path)
		}
	}
}

func TestMatchesTarget_EmptyPatternMatchesAnything(t *testing.T) {
	paths := []string{"/api", "/health", ""}
	for _, path := range paths {
		if !matchesTarget("", path) {
			t.Errorf("matchesTarget('', %q) = false, want true", path)
		}
	}
}

func TestMatchesTarget_ExactMatch(t *testing.T) {
	if !matchesTarget("/api/v1/scans", "/api/v1/scans") {
		t.Error("matchesTarget exact path: want true, got false")
	}
}

func TestMatchesTarget_CaseInsensitiveExactMatch(t *testing.T) {
	if !matchesTarget("/API/V1/SCANS", "/api/v1/scans") {
		t.Error("matchesTarget case-insensitive: want true, got false")
	}
}

func TestMatchesTarget_NoMatchDifferentPath(t *testing.T) {
	if matchesTarget("/api/v1/scans", "/api/v1/findings") {
		t.Error("matchesTarget different paths: want false, got true")
	}
}

// ---------------------------------------------------------------------------
// matchesMethod (HTTP method matching)
// ---------------------------------------------------------------------------

func TestMatchesMethod_WildcardMatchesAllMethods(t *testing.T) {
	methods := []string{"GET", "POST", "DELETE", "PATCH", "OPTIONS", "PUT"}
	for _, m := range methods {
		if !matchesMethod("*", m) {
			t.Errorf("matchesMethod('*', %q) = false, want true", m)
		}
	}
}

func TestMatchesMethod_EmptyPatternMatchesAll(t *testing.T) {
	methods := []string{"GET", "POST"}
	for _, m := range methods {
		if !matchesMethod("", m) {
			t.Errorf("matchesMethod('', %q) = false, want true", m)
		}
	}
}

func TestMatchesMethod_ExactMatch(t *testing.T) {
	if !matchesMethod("GET", "GET") {
		t.Error("matchesMethod exact: want true, got false")
	}
}

func TestMatchesMethod_CaseInsensitiveMatch(t *testing.T) {
	if !matchesMethod("get", "GET") {
		t.Error("matchesMethod case-insensitive: want true, got false")
	}
}

func TestMatchesMethod_NoMatchDifferentMethod(t *testing.T) {
	if matchesMethod("POST", "GET") {
		t.Error("matchesMethod different methods: want false, got true")
	}
}

// ---------------------------------------------------------------------------
// parseSeverity (severity mapping)
// ---------------------------------------------------------------------------

func TestParseSeverity_Critical(t *testing.T) {
	if got := parseSeverity("critical"); got != domain.SeverityCritical {
		t.Errorf("parseSeverity('critical') = %q, want %q", got, domain.SeverityCritical)
	}
}

func TestParseSeverity_High(t *testing.T) {
	if got := parseSeverity("high"); got != domain.SeverityHigh {
		t.Errorf("parseSeverity('high') = %q, want %q", got, domain.SeverityHigh)
	}
}

func TestParseSeverity_Medium(t *testing.T) {
	if got := parseSeverity("medium"); got != domain.SeverityMedium {
		t.Errorf("parseSeverity('medium') = %q, want %q", got, domain.SeverityMedium)
	}
}

func TestParseSeverity_Low(t *testing.T) {
	if got := parseSeverity("low"); got != domain.SeverityLow {
		t.Errorf("parseSeverity('low') = %q, want %q", got, domain.SeverityLow)
	}
}

func TestParseSeverity_Info(t *testing.T) {
	if got := parseSeverity("info"); got != domain.SeverityInfo {
		t.Errorf("parseSeverity('info') = %q, want %q", got, domain.SeverityInfo)
	}
}

func TestParseSeverity_UnknownDefaultsToInfo(t *testing.T) {
	unknowns := []string{"extreme", "UNKNOWN", "", "n/a"}
	for _, s := range unknowns {
		got := parseSeverity(s)
		if got != domain.SeverityInfo {
			t.Errorf("parseSeverity(%q) = %q, want %q (info default)", s, got, domain.SeverityInfo)
		}
	}
}

func TestParseSeverity_CaseInsensitive(t *testing.T) {
	cases := map[string]domain.Severity{
		"HIGH":     domain.SeverityHigh,
		"High":     domain.SeverityHigh,
		"MEDIUM":   domain.SeverityMedium,
		"LOW":      domain.SeverityLow,
		"CRITICAL": domain.SeverityCritical,
		"INFO":     domain.SeverityInfo,
	}
	for input, want := range cases {
		if got := parseSeverity(input); got != want {
			t.Errorf("parseSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// NewModule (ID/Name delegation)
// ---------------------------------------------------------------------------

// TestNewModule_IDandName verifies that NewModule wraps the rule correctly and
// that ID() and Name() delegate to the rule's fields.
func TestNewModule_IDandName(t *testing.T) {
	r := CustomRule{
		ID:       "CR-007",
		Name:     "Seven Rule",
		Severity: "medium",
		Enabled:  true,
	}
	m := NewModule(r)

	if m.ID() != "CR-007" {
		t.Errorf("module.ID() = %q, want CR-007", m.ID())
	}
	if m.Name() != "Seven Rule" {
		t.Errorf("module.Name() = %q, want 'Seven Rule'", m.Name())
	}
}

// TestNewModule_EmptyID verifies that a rule with an empty ID is wrapped without
// alteration — validation is the loader's responsibility, not NewModule.
func TestNewModule_EmptyID(t *testing.T) {
	r := CustomRule{Name: "Unnamed", Severity: "low", Enabled: true}
	m := NewModule(r)

	if m.ID() != "" {
		t.Errorf("module.ID() = %q, want empty string for rule with no ID", m.ID())
	}
}

// ---------------------------------------------------------------------------
// Check struct fields
// ---------------------------------------------------------------------------

// TestCheck_Fields verifies that all exported fields on Check are assignable.
func TestCheck_Fields(t *testing.T) {
	c := Check{
		Type:    "status_code",
		Target:  "*",
		Method:  "GET",
		Message: "Unexpected status code",
		Params:  map[string]string{"expected": "401,403"},
	}

	if c.Type != "status_code" {
		t.Errorf("Type = %q, want 'status_code'", c.Type)
	}
	if c.Target != "*" {
		t.Errorf("Target = %q, want '*'", c.Target)
	}
	if c.Method != "GET" {
		t.Errorf("Method = %q, want 'GET'", c.Method)
	}
	if c.Params["expected"] != "401,403" {
		t.Errorf("Params[expected] = %q, want '401,403'", c.Params["expected"])
	}
}
