package customrules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeValidRule returns a fully-populated CustomRule that passes Validate.
func makeValidRule() CustomRule {
	return CustomRule{
		ID:       "CR-001",
		Name:     "Test Rule",
		Severity: "high",
		Enabled:  true,
		Checks: []Check{
			{
				Type:    "header_missing",
				Target:  "*",
				Method:  "*",
				Message: "Missing required header",
				Params:  map[string]string{"header": "X-Request-ID"},
			},
		},
	}
}

// writeTempYAML writes content to a new temp file in dir with the given filename
// and returns the full path.
func writeTempYAML(t *testing.T, dir, filename, content string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeTempYAML: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// LoadRulesFromFile
// ---------------------------------------------------------------------------

func TestLoadRulesFromFile_OneRule(t *testing.T) {
	dir := t.TempDir()
	path := writeTempYAML(t, dir, "rules.yaml", `
rules:
  - id: CR-001
    name: Test Rule
    severity: high
    enabled: true
    checks:
      - type: header_missing
        target: "*"
        method: "*"
        message: Missing header
        params:
          header: X-Request-ID
`)

	rules, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.ID != "CR-001" {
		t.Errorf("expected ID CR-001, got %q", r.ID)
	}
	if r.Name != "Test Rule" {
		t.Errorf("expected Name 'Test Rule', got %q", r.Name)
	}
	if r.Severity != "high" {
		t.Errorf("expected Severity 'high', got %q", r.Severity)
	}
	if !r.Enabled {
		t.Error("expected Enabled true")
	}
}

func TestLoadRulesFromFile_MultipleRules(t *testing.T) {
	dir := t.TempDir()
	path := writeTempYAML(t, dir, "rules.yaml", `
rules:
  - id: CR-001
    name: Rule One
    severity: high
    enabled: true
    checks:
      - type: header_missing
        target: "*"
        method: "*"
        message: msg
        params:
          header: X-A
  - id: CR-002
    name: Rule Two
    severity: low
    enabled: true
    checks:
      - type: status_code
        target: "*"
        method: GET
        message: msg2
        params:
          expected: "401"
  - id: CR-003
    name: Rule Three
    severity: info
    enabled: true
    checks:
      - type: response_body_contains
        target: /api
        method: POST
        message: msg3
        params:
          text: secret
`)

	rules, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	ids := []string{rules[0].ID, rules[1].ID, rules[2].ID}
	for i, want := range []string{"CR-001", "CR-002", "CR-003"} {
		if ids[i] != want {
			t.Errorf("rules[%d].ID = %q, want %q", i, ids[i], want)
		}
	}
}

func TestLoadRulesFromFile_EnabledDefaultsTrue_WhenKeyAbsent(t *testing.T) {
	dir := t.TempDir()
	// "enabled" key is intentionally absent
	path := writeTempYAML(t, dir, "rules.yaml", `
rules:
  - id: CR-001
    name: Rule One
    severity: high
    checks:
      - type: header_missing
        target: "*"
        method: "*"
        message: msg
        params:
          header: X-A
`)

	rules, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if !rules[0].Enabled {
		t.Error("expected Enabled to default to true when key is absent")
	}
}

func TestLoadRulesFromFile_EnabledFalse_WhenExplicitlySet(t *testing.T) {
	dir := t.TempDir()
	path := writeTempYAML(t, dir, "rules.yaml", `
rules:
  - id: CR-001
    name: Rule One
    severity: high
    enabled: false
    checks:
      - type: header_missing
        target: "*"
        method: "*"
        message: msg
        params:
          header: X-A
`)

	rules, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Enabled {
		t.Error("expected Enabled to remain false when explicitly set to false")
	}
}

func TestLoadRulesFromFile_NonExistentFile(t *testing.T) {
	_, err := LoadRulesFromFile("/does/not/exist/rules.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}

func TestLoadRulesFromFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := writeTempYAML(t, dir, "bad.yaml", `
rules:
  - id: [unclosed bracket
    name: oops
`)

	_, err := LoadRulesFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadRulesFromFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := writeTempYAML(t, dir, "empty.yaml", ``)

	rules, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error for empty file: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

// ---------------------------------------------------------------------------
// LoadRulesFromDir
// ---------------------------------------------------------------------------

func TestLoadRulesFromDir_TwoValidFiles(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "a.yaml", `
rules:
  - id: CR-001
    name: Rule A
    severity: high
    enabled: true
    checks:
      - type: header_missing
        target: "*"
        method: "*"
        message: msg
        params:
          header: X-A
`)
	writeTempYAML(t, dir, "b.yml", `
rules:
  - id: CR-002
    name: Rule B
    severity: low
    enabled: true
    checks:
      - type: status_code
        target: "*"
        method: GET
        message: msg
        params:
          expected: "403"
`)

	rules, err := LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestLoadRulesFromDir_OneValidOneInvalid(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "good.yaml", `
rules:
  - id: CR-001
    name: Good Rule
    severity: high
    enabled: true
    checks:
      - type: header_missing
        target: "*"
        method: "*"
        message: msg
        params:
          header: X-A
`)
	writeTempYAML(t, dir, "bad.yaml", `
rules:
  - id: [unclosed
`)

	rules, err := LoadRulesFromDir(dir)
	if err == nil {
		t.Fatal("expected non-nil error when one file is invalid")
	}
	// The valid file's rules should still be returned.
	if len(rules) != 1 {
		t.Errorf("expected 1 rule from valid file, got %d", len(rules))
	}
}

func TestLoadRulesFromDir_NonExistentDirectory(t *testing.T) {
	_, err := LoadRulesFromDir("/does/not/exist/dir")
	if err == nil {
		t.Fatal("expected error for non-existent directory, got nil")
	}
}

func TestLoadRulesFromDir_NonYAMLFilesSkipped(t *testing.T) {
	dir := t.TempDir()
	// Write a non-YAML file — should be silently skipped.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not yaml"), 0o644); err != nil {
		t.Fatalf("write txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"key":"val"}`), 0o644); err != nil {
		t.Fatalf("write json: %v", err)
	}
	// Also add one valid YAML so we confirm yaml files are still picked up.
	writeTempYAML(t, dir, "rules.yaml", `
rules:
  - id: CR-001
    name: Rule A
    severity: high
    enabled: true
    checks:
      - type: header_missing
        target: "*"
        method: "*"
        message: msg
        params:
          header: X-A
`)

	rules, err := LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule (non-yaml files skipped), got %d", len(rules))
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidate_ValidRule(t *testing.T) {
	rules := []CustomRule{makeValidRule()}
	errs := Validate(rules)
	if len(errs) != 0 {
		t.Errorf("expected no errors for valid rule, got: %v", errs)
	}
}

func TestValidate_MissingID(t *testing.T) {
	r := makeValidRule()
	r.ID = ""
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "id is required") {
		t.Errorf("expected error about id required, got: %v", errs)
	}
}

func TestValidate_MissingName(t *testing.T) {
	r := makeValidRule()
	r.Name = ""
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "name is required") {
		t.Errorf("expected error about name required, got: %v", errs)
	}
}

func TestValidate_UnknownSeverity(t *testing.T) {
	r := makeValidRule()
	r.Severity = "extreme"
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "unknown severity") {
		t.Errorf("expected error about unknown severity, got: %v", errs)
	}
}

func TestValidate_NoChecks(t *testing.T) {
	r := makeValidRule()
	r.Checks = nil
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "at least one check is required") {
		t.Errorf("expected error about checks required, got: %v", errs)
	}
}

func TestValidate_CheckMissingType(t *testing.T) {
	r := makeValidRule()
	r.Checks[0].Type = ""
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "type is required") {
		t.Errorf("expected error about type required, got: %v", errs)
	}
}

func TestValidate_CheckUnknownType(t *testing.T) {
	r := makeValidRule()
	r.Checks[0].Type = "does_not_exist"
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "unknown check type") {
		t.Errorf("expected error about unknown check type, got: %v", errs)
	}
}

func TestValidate_CheckMissingTarget(t *testing.T) {
	r := makeValidRule()
	r.Checks[0].Target = ""
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "target is required") {
		t.Errorf("expected error about target required, got: %v", errs)
	}
}

func TestValidate_CheckMissingMethod(t *testing.T) {
	r := makeValidRule()
	r.Checks[0].Method = ""
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "method is required") {
		t.Errorf("expected error about method required, got: %v", errs)
	}
}

func TestValidate_CheckMissingMessage(t *testing.T) {
	r := makeValidRule()
	r.Checks[0].Message = ""
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "message is required") {
		t.Errorf("expected error about message required, got: %v", errs)
	}
}

func TestValidate_HeaderMissingCheck_MissingParamsHeader(t *testing.T) {
	r := makeValidRule()
	r.Checks[0].Type = "header_missing"
	r.Checks[0].Params = map[string]string{} // header key absent
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "params.header is required") {
		t.Errorf("expected error about params.header, got: %v", errs)
	}
}

func TestValidate_HeaderValueCheck_MissingParamsPattern(t *testing.T) {
	r := makeValidRule()
	r.Checks[0].Type = "header_value"
	r.Checks[0].Params = map[string]string{"header": "X-Request-ID"} // pattern absent
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "params.pattern is required") {
		t.Errorf("expected error about params.pattern, got: %v", errs)
	}
}

func TestValidate_StatusCodeCheck_MissingParamsExpected(t *testing.T) {
	r := makeValidRule()
	r.Checks[0].Type = "status_code"
	r.Checks[0].Params = map[string]string{} // expected absent
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "params.expected is required") {
		t.Errorf("expected error about params.expected, got: %v", errs)
	}
}

func TestValidate_ResponseBodyContainsCheck_MissingParamsText(t *testing.T) {
	r := makeValidRule()
	r.Checks[0].Type = "response_body_contains"
	r.Checks[0].Params = map[string]string{} // text absent
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "params.text is required") {
		t.Errorf("expected error about params.text, got: %v", errs)
	}
}

func TestValidate_ResponseTimeExceedsCheck_MissingParamsMs(t *testing.T) {
	r := makeValidRule()
	r.Checks[0].Type = "response_time_exceeds"
	r.Checks[0].Params = map[string]string{} // ms absent
	errs := Validate([]CustomRule{r})
	if !containsError(errs, "params.ms is required") {
		t.Errorf("expected error about params.ms, got: %v", errs)
	}
}

func TestValidate_DuplicateRuleIDs(t *testing.T) {
	r1 := makeValidRule() // ID = "CR-001"
	r2 := makeValidRule() // ID = "CR-001" — duplicate
	errs := Validate([]CustomRule{r1, r2})
	if !containsError(errs, "duplicate rule id") {
		t.Errorf("expected error about duplicate rule id, got: %v", errs)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// containsError reports whether any error in errs contains the substring needle.
func containsError(errs []error, needle string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), needle) {
			return true
		}
	}
	return false
}
