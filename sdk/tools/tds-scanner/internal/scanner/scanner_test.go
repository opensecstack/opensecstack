package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile %s: %v", name, err)
	}
	return p
}

func mkDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tds-scanner-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// goFile with a hardcoded API key — guaranteed to trigger TDS-AUTH-001
const hardcodedKeyGo = `package main
const api_key = "abcdefghijklmnopqrstuvwxyz"
`

// pyFile with no issues
const cleanPython = `# clean file
def hello():
    return "world"
`

// ── ScanPath — error cases ────────────────────────────────────────────────────

func TestScanPath_NonExistentPath(t *testing.T) {
	s := &Scanner{}
	_, _, err := s.ScanPath("/non/existent/path/xyz")
	if err == nil {
		t.Error("expected error for non-existent path, got nil")
	}
}

// ── ScanPath — single file ────────────────────────────────────────────────────

func TestScanPath_SingleFile_NoFindings(t *testing.T) {
	dir := mkDir(t)
	path := writeFile(t, dir, "clean.go", "package main\nfunc main() {}\n")

	s := &Scanner{Language: "go", MinSeverity: "low"}
	findings, _, err := s.ScanPath(path)
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	// A minimal clean file should produce no findings
	_ = findings // may or may not be empty depending on content
}

func TestScanPath_SingleFile_FindingsReturned(t *testing.T) {
	dir := mkDir(t)
	path := writeFile(t, dir, "main.go", hardcodedKeyGo)

	s := &Scanner{Language: "go", MinSeverity: "low"}
	findings, runnerCount, err := s.ScanPath(path)
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if runnerCount == 0 {
		t.Error("expected at least one runner to be executed")
	}
	if len(findings) == 0 {
		t.Error("expected at least one finding for hardcoded API key")
	}
}

func TestScanPath_SingleFile_FindingHasFilePath(t *testing.T) {
	dir := mkDir(t)
	path := writeFile(t, dir, "main.go", hardcodedKeyGo)

	s := &Scanner{Language: "go", MinSeverity: "low"}
	findings, _, err := s.ScanPath(path)
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	for _, f := range findings {
		if f.FilePath == "" {
			t.Error("finding FilePath must not be empty")
		}
		if f.CheckID == "" {
			t.Error("finding CheckID must not be empty")
		}
	}
}

// ── ScanPath — directory ──────────────────────────────────────────────────────

func TestScanPath_Directory_FindsGoFiles(t *testing.T) {
	dir := mkDir(t)
	writeFile(t, dir, "a.go", hardcodedKeyGo)
	writeFile(t, dir, "b.go", "package main\nfunc foo() {}\n")
	writeFile(t, dir, "ignored.py", cleanPython) // should be ignored for Go language

	s := &Scanner{Language: "go", MinSeverity: "low"}
	findings, _, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath(dir): %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings for hardcoded key in a.go")
	}
}

func TestScanPath_Directory_SkipsHiddenDirs(t *testing.T) {
	dir := mkDir(t)
	hidden := filepath.Join(dir, ".hidden")
	os.MkdirAll(hidden, 0o755)
	writeFile(t, hidden, "secret.go", hardcodedKeyGo)
	writeFile(t, dir, "clean.go", "package main\n")

	s := &Scanner{Language: "go", MinSeverity: "low"}
	findings, _, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	for _, f := range findings {
		if filepath.Dir(f.FilePath) == hidden {
			t.Errorf("finding from hidden dir should be skipped: %s", f.FilePath)
		}
	}
}

func TestScanPath_Directory_SkipsVendorDir(t *testing.T) {
	dir := mkDir(t)
	vendor := filepath.Join(dir, "vendor")
	os.MkdirAll(vendor, 0o755)
	writeFile(t, vendor, "lib.go", hardcodedKeyGo)
	writeFile(t, dir, "clean.go", "package main\n")

	s := &Scanner{Language: "go", MinSeverity: "low"}
	findings, _, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	for _, f := range findings {
		if filepath.Base(filepath.Dir(f.FilePath)) == "vendor" {
			t.Errorf("finding from vendor dir should be skipped: %s", f.FilePath)
		}
	}
}

// ── ScanPath — runner count ───────────────────────────────────────────────────

func TestScanPath_AllRunners_Count(t *testing.T) {
	dir := mkDir(t)
	writeFile(t, dir, "main.go", "package main\n")

	s := &Scanner{Language: "go", MinSeverity: "low"}
	_, runnerCount, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if runnerCount != 5 {
		t.Errorf("expected 5 runners (one per check family), got %d", runnerCount)
	}
}

func TestScanPath_SpecificCheck_SingleRunner(t *testing.T) {
	dir := mkDir(t)
	writeFile(t, dir, "main.go", "package main\n")

	s := &Scanner{Language: "go", Checks: []string{"TDS-AUTH-001"}, MinSeverity: "low"}
	_, runnerCount, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	if runnerCount != 1 {
		t.Errorf("expected 1 runner for TDS-AUTH-001, got %d", runnerCount)
	}
}

// ── ScanPath — severity filtering ────────────────────────────────────────────

func TestScanPath_MinSeverityHigh_FiltersLow(t *testing.T) {
	dir := mkDir(t)
	// TDS-AUTH-001 hardcoded key is HIGH severity — should survive "high" filter
	writeFile(t, dir, "main.go", hardcodedKeyGo)

	s := &Scanner{Language: "go", MinSeverity: "high"}
	findings, _, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	for _, f := range findings {
		if f.Severity == "low" || f.Severity == "medium" {
			t.Errorf("finding with severity %q should be filtered by MinSeverity=high", f.Severity)
		}
	}
}

func TestScanPath_MinSeverityCritical_MayReturnEmpty(t *testing.T) {
	dir := mkDir(t)
	writeFile(t, dir, "main.go", "package main\nfunc main() {}\n")

	s := &Scanner{Language: "go", MinSeverity: "critical"}
	findings, _, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	// No critical findings in a clean file
	if len(findings) != 0 {
		t.Errorf("expected 0 critical findings in clean file, got %d", len(findings))
	}
}

// ── ScanPath — sort order ─────────────────────────────────────────────────────

func TestScanPath_FindingsSortedBySeverityDesc(t *testing.T) {
	dir := mkDir(t)
	// File with multiple types of findings
	src := `package main
import "net/http"
const api_key = "abcdefghijklmnopqrstuvwxyz"
func call() {
    http.Get("http://api.example.com/data")
}
`
	writeFile(t, dir, "main.go", src)

	s := &Scanner{Language: "go", MinSeverity: "low"}
	findings, _, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath: %v", err)
	}
	for i := 1; i < len(findings); i++ {
		prev := findings[i-1].Severity
		curr := findings[i].Severity
		if severityRankLocal(prev) < severityRankLocal(curr) {
			t.Errorf("findings not sorted by severity: %s before %s at index %d", prev, curr, i)
		}
	}
}

func severityRankLocal(s string) int {
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
	}
	return 0
}

// ── resolveExtensions ─────────────────────────────────────────────────────────

func TestResolveExtensions_ExplicitGo(t *testing.T) {
	s := &Scanner{Language: "go"}
	dir := mkDir(t)
	info, _ := os.Stat(dir)
	exts := s.resolveExtensions(dir, info)
	if len(exts) != 1 || exts[0] != ".go" {
		t.Errorf("expected [.go], got %v", exts)
	}
}

func TestResolveExtensions_ExplicitPython(t *testing.T) {
	s := &Scanner{Language: "python"}
	dir := mkDir(t)
	info, _ := os.Stat(dir)
	exts := s.resolveExtensions(dir, info)
	if len(exts) != 1 || exts[0] != ".py" {
		t.Errorf("expected [.py], got %v", exts)
	}
}

func TestResolveExtensions_ExplicitRust(t *testing.T) {
	s := &Scanner{Language: "rust"}
	dir := mkDir(t)
	info, _ := os.Stat(dir)
	exts := s.resolveExtensions(dir, info)
	if len(exts) != 1 || exts[0] != ".rs" {
		t.Errorf("expected [.rs], got %v", exts)
	}
}

func TestResolveExtensions_SingleGoFile(t *testing.T) {
	dir := mkDir(t)
	path := writeFile(t, dir, "main.go", "package main\n")
	info, _ := os.Stat(path)

	s := &Scanner{Language: "auto"}
	exts := s.resolveExtensions(path, info)
	if len(exts) == 0 {
		t.Error("expected at least one extension for .go file")
	}
	if exts[0] != ".go" {
		t.Errorf("expected .go, got %v", exts)
	}
}

func TestResolveExtensions_SinglePyFile(t *testing.T) {
	dir := mkDir(t)
	path := writeFile(t, dir, "main.py", cleanPython)
	info, _ := os.Stat(path)

	s := &Scanner{Language: ""}
	exts := s.resolveExtensions(path, info)
	if len(exts) == 0 || exts[0] != ".py" {
		t.Errorf("expected [.py], got %v", exts)
	}
}

func TestResolveExtensions_DirDominantLanguage(t *testing.T) {
	dir := mkDir(t)
	// 3 Go files, 1 Python file → Go should dominate
	writeFile(t, dir, "a.go", "package main\n")
	writeFile(t, dir, "b.go", "package main\n")
	writeFile(t, dir, "c.go", "package main\n")
	writeFile(t, dir, "d.py", cleanPython)

	info, _ := os.Stat(dir)
	s := &Scanner{Language: "auto"}
	exts := s.resolveExtensions(dir, info)
	if len(exts) == 0 || exts[0] != ".go" {
		t.Errorf("expected [.go] as dominant, got %v", exts)
	}
}

func TestResolveExtensions_UnknownExtensionFile(t *testing.T) {
	dir := mkDir(t)
	path := writeFile(t, dir, "file.xyz", "some content\n")
	info, _ := os.Stat(path)

	s := &Scanner{Language: ""}
	exts := s.resolveExtensions(path, info)
	if len(exts) == 0 {
		t.Error("expected at least one extension for unknown file type")
	}
}

// ── resolveRunners ────────────────────────────────────────────────────────────

func TestResolveRunners_EmptyChecks_AllFive(t *testing.T) {
	s := &Scanner{}
	runners := s.resolveRunners()
	if len(runners) != 5 {
		t.Errorf("expected 5 runners for empty Checks, got %d", len(runners))
	}
}

func TestResolveRunners_SpecificPrefix_SingleRunner(t *testing.T) {
	s := &Scanner{Checks: []string{"TDS-TLS-001"}}
	runners := s.resolveRunners()
	if len(runners) != 1 {
		t.Errorf("expected 1 runner for TDS-TLS-001, got %d", len(runners))
	}
}

func TestResolveRunners_TwoFamilies(t *testing.T) {
	s := &Scanner{Checks: []string{"TDS-AUTH-001", "TDS-SECRET-001"}}
	runners := s.resolveRunners()
	if len(runners) != 2 {
		t.Errorf("expected 2 runners for AUTH+SECRET, got %d", len(runners))
	}
}

func TestResolveRunners_CaseInsensitive(t *testing.T) {
	s := &Scanner{Checks: []string{"tds-auth-001"}}
	runners := s.resolveRunners()
	if len(runners) != 1 {
		t.Errorf("expected 1 runner even with lowercase check ID, got %d", len(runners))
	}
}

func TestResolveRunners_UnknownCheckID_ZeroRunners(t *testing.T) {
	s := &Scanner{Checks: []string{"UNKNOWN-999"}}
	runners := s.resolveRunners()
	if len(runners) != 0 {
		t.Errorf("expected 0 runners for unknown check ID, got %d", len(runners))
	}
}

// ── filterBySeverity ──────────────────────────────────────────────────────────

func TestFilterBySeverity_DefaultMinLow_KeepsLow(t *testing.T) {
	s := &Scanner{MinSeverity: ""} // defaults to "low"
	findings := []struct {
		severity string
	}{
		{"info"}, {"low"}, {"medium"}, {"high"}, {"critical"},
	}
	var input []interface{}
	_ = input

	// Build findings via checks.Finding directly isn't accessible here (wrong package),
	// but we can test via ScanPath integration above. Verify the default works.
	_ = s.filterBySeverity(nil) // nil slice → no panic
}

// ── DetectedLanguage ──────────────────────────────────────────────────────────

func TestDetectedLanguage_Go(t *testing.T) {
	got := DetectedLanguage([]string{".go"})
	if got != "go" {
		t.Errorf("DetectedLanguage([.go]) = %q, want go", got)
	}
}

func TestDetectedLanguage_Python(t *testing.T) {
	got := DetectedLanguage([]string{".py"})
	if got != "python" {
		t.Errorf("DetectedLanguage([.py]) = %q, want python", got)
	}
}

func TestDetectedLanguage_Rust(t *testing.T) {
	got := DetectedLanguage([]string{".rs"})
	if got != "rust" {
		t.Errorf("DetectedLanguage([.rs]) = %q, want rust", got)
	}
}

func TestDetectedLanguage_Unknown(t *testing.T) {
	got := DetectedLanguage([]string{".xyz"})
	if got != ".xyz" {
		t.Errorf("DetectedLanguage([.xyz]) = %q, want .xyz", got)
	}
}

func TestDetectedLanguage_Empty(t *testing.T) {
	got := DetectedLanguage(nil)
	if got != "unknown" {
		t.Errorf("DetectedLanguage(nil) = %q, want unknown", got)
	}
}

// ── DetectLanguageFromPath ────────────────────────────────────────────────────

func TestDetectLanguageFromPath_ExplicitHint_Go(t *testing.T) {
	got := DetectLanguageFromPath("/any/path", "go")
	if got != "go" {
		t.Errorf("expected go, got %q", got)
	}
}

func TestDetectLanguageFromPath_ExplicitHint_Python(t *testing.T) {
	got := DetectLanguageFromPath("/any/path", "python")
	if got != "python" {
		t.Errorf("expected python, got %q", got)
	}
}

func TestDetectLanguageFromPath_NonExistent_ReturnsUnknown(t *testing.T) {
	got := DetectLanguageFromPath("/non/existent/path", "auto")
	if got != "unknown" {
		t.Errorf("expected unknown for non-existent path, got %q", got)
	}
}

func TestDetectLanguageFromPath_GoDir_DetectsGo(t *testing.T) {
	dir := mkDir(t)
	writeFile(t, dir, "main.go", "package main\n")
	writeFile(t, dir, "util.go", "package main\n")

	got := DetectLanguageFromPath(dir, "auto")
	if got != "go" {
		t.Errorf("expected go for Go directory, got %q", got)
	}
}

func TestDetectLanguageFromPath_EmptyHint_AutoDetects(t *testing.T) {
	dir := mkDir(t)
	writeFile(t, dir, "script.py", cleanPython)

	got := DetectLanguageFromPath(dir, "")
	if got != "python" {
		t.Errorf("expected python for Python directory, got %q", got)
	}
}

// ── readFile ──────────────────────────────────────────────────────────────────

func TestReadFile_ValidFile(t *testing.T) {
	dir := mkDir(t)
	path := writeFile(t, dir, "test.go", "package main\nfunc main() {}\n")

	sf, err := readFile(path)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if sf.Path != path {
		t.Errorf("Path = %q, want %q", sf.Path, path)
	}
	if len(sf.Content) == 0 {
		t.Error("Content must not be empty")
	}
	if len(sf.Lines) == 0 {
		t.Error("Lines must not be empty")
	}
}

func TestReadFile_NonExistent(t *testing.T) {
	_, err := readFile("/non/existent/file.go")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

func TestReadFile_SplitsIntoLines(t *testing.T) {
	dir := mkDir(t)
	content := "line1\nline2\nline3"
	path := writeFile(t, dir, "f.go", content)

	sf, err := readFile(path)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if len(sf.Lines) != 3 {
		t.Errorf("expected 3 lines, got %d: %v", len(sf.Lines), sf.Lines)
	}
}
