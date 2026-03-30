package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/opensecstack/tds-scanner/internal/checks"
)

// Scanner orchestrates all TDS compliance checks across a target path.
type Scanner struct {
	// MinSeverity is the minimum severity level to include in results.
	// Accepted values: "info", "low", "medium", "high", "critical".
	MinSeverity string

	// Checks is an optional allow-list of check IDs (e.g. ["TDS-AUTH-001"]).
	// An empty slice means "run all checks".
	Checks []string

	// Language is a hint for which source files to load.
	// Accepted values: "go", "python", "rust", "auto".
	Language string
}

// extensionsByLanguage maps language hints to their canonical file extensions.
var extensionsByLanguage = map[string][]string{
	"go":     {".go"},
	"python": {".py"},
	"rust":   {".rs"},
}

// checkRunners maps a check-ID prefix to the function that runs those checks.
type checkRunner func([]checks.ScannedFile) []checks.Finding

var allRunners = map[string]checkRunner{
	"TDS-AUTH":   checks.RunAuthChecks,
	"TDS-TLS":    checks.RunTLSChecks,
	"TDS-RETRY":  checks.RunRetryChecks,
	"TDS-SECRET": checks.RunSecretChecks,
	"TDS-HDR":    checks.RunHeaderChecks,
}

// ScanPath walks path (file or directory), loads matching source files, runs
// the enabled checks, filters by MinSeverity, and returns findings sorted from
// most to least severe.
func (s *Scanner) ScanPath(path string) ([]checks.Finding, int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("cannot stat %s: %w", path, err)
	}

	exts := s.resolveExtensions(path, info)
	scannedFiles, err := s.loadFiles(path, info, exts)
	if err != nil {
		return nil, 0, err
	}

	runners := s.resolveRunners()
	var raw []checks.Finding
	for _, run := range runners {
		raw = append(raw, run(scannedFiles)...)
	}

	filtered := s.filterBySeverity(raw)
	sort.Slice(filtered, func(i, j int) bool {
		ri := checks.SeverityRank(filtered[i].Severity)
		rj := checks.SeverityRank(filtered[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if filtered[i].FilePath != filtered[j].FilePath {
			return filtered[i].FilePath < filtered[j].FilePath
		}
		return filtered[i].Line < filtered[j].Line
	})

	return filtered, len(runners), nil
}

// resolveExtensions decides which file extensions to scan.
func (s *Scanner) resolveExtensions(path string, info os.FileInfo) []string {
	lang := strings.ToLower(s.Language)
	if lang != "" && lang != "auto" {
		if exts, ok := extensionsByLanguage[lang]; ok {
			return exts
		}
	}

	// Auto-detect: if the target is a single file, derive from its extension.
	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(path))
		for _, exts := range extensionsByLanguage {
			for _, e := range exts {
				if e == ext {
					return []string{ext}
				}
			}
		}
		// Unknown extension — scan anyway.
		return []string{filepath.Ext(path)}
	}

	// Auto-detect by counting file extensions in the directory tree.
	counts := map[string]int{}
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		for _, exts := range extensionsByLanguage {
			for _, e := range exts {
				if e == ext {
					counts[ext]++
				}
			}
		}
		return nil
	})

	if len(counts) == 0 {
		// Fall back to scanning everything we know about.
		var all []string
		for _, exts := range extensionsByLanguage {
			all = append(all, exts...)
		}
		return all
	}

	// Return the extension(s) belonging to the dominant language.
	var dominant string
	var maxCount int
	for ext, n := range counts {
		if n > maxCount {
			maxCount = n
			dominant = ext
		}
	}
	for lang, exts := range extensionsByLanguage {
		_ = lang
		for _, e := range exts {
			if e == dominant {
				return exts
			}
		}
	}
	return []string{dominant}
}

// loadFiles reads source files from path that match the allowed extensions.
func (s *Scanner) loadFiles(path string, info os.FileInfo, exts []string) ([]checks.ScannedFile, error) {
	extSet := map[string]bool{}
	for _, e := range exts {
		extSet[strings.ToLower(e)] = true
	}

	var files []checks.ScannedFile

	if !info.IsDir() {
		sf, err := readFile(path)
		if err != nil {
			return nil, err
		}
		files = append(files, sf)
		return files, nil
	}

	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable paths
		}
		if d.IsDir() {
			// Skip hidden directories and common vendor/cache paths.
			base := d.Name()
			if strings.HasPrefix(base, ".") || base == "vendor" || base == "node_modules" || base == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if !extSet[ext] {
			return nil
		}
		sf, err := readFile(p)
		if err != nil {
			return nil // skip unreadable files
		}
		files = append(files, sf)
		return nil
	})

	return files, err
}

// resolveRunners returns the check functions to run based on s.Checks.
func (s *Scanner) resolveRunners() []checkRunner {
	if len(s.Checks) == 0 {
		// Run all.
		var runners []checkRunner
		// Deterministic order.
		for _, prefix := range []string{"TDS-AUTH", "TDS-TLS", "TDS-RETRY", "TDS-SECRET", "TDS-HDR"} {
			runners = append(runners, allRunners[prefix])
		}
		return runners
	}

	// Build a set of requested check IDs.
	requested := map[string]bool{}
	for _, id := range s.Checks {
		requested[strings.ToUpper(strings.TrimSpace(id))] = true
	}

	// For each runner, include it if any of its check IDs are requested.
	// We determine which check IDs a runner covers by its prefix key.
	runnerSet := map[string]bool{}
	for id := range requested {
		for prefix := range allRunners {
			if strings.HasPrefix(id, prefix) {
				runnerSet[prefix] = true
			}
		}
	}

	var runners []checkRunner
	for _, prefix := range []string{"TDS-AUTH", "TDS-TLS", "TDS-RETRY", "TDS-SECRET", "TDS-HDR"} {
		if runnerSet[prefix] {
			runners = append(runners, allRunners[prefix])
		}
	}
	return runners
}

// filterBySeverity removes findings below the minimum severity threshold.
func (s *Scanner) filterBySeverity(findings []checks.Finding) []checks.Finding {
	minRank := checks.SeverityRank(s.MinSeverity)
	if minRank == 0 {
		minRank = checks.SeverityRank("low")
	}
	var out []checks.Finding
	for _, f := range findings {
		if checks.SeverityRank(f.Severity) >= minRank {
			out = append(out, f)
		}
	}
	return out
}

// readFile loads a file from disk and splits it into lines.
func readFile(path string) (checks.ScannedFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return checks.ScannedFile{}, fmt.Errorf("read %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	return checks.ScannedFile{
		Path:    path,
		Content: data,
		Lines:   lines,
	}, nil
}

// DetectedLanguage returns a human-readable string for the language inferred
// from the extensions that were scanned.
func DetectedLanguage(exts []string) string {
	if len(exts) == 0 {
		return "unknown"
	}
	for lang, langExts := range extensionsByLanguage {
		for _, e := range langExts {
			if e == exts[0] {
				return lang
			}
		}
	}
	return exts[0]
}

// DetectLanguageFromPath inspects the files under path and returns the
// dominant language name (e.g. "go", "python", "rust").  If langHint is
// already an explicit language (not "auto"), it is returned as-is.
func DetectLanguageFromPath(path string, langHint string) string {
	hint := strings.ToLower(langHint)
	if hint != "" && hint != "auto" {
		return hint
	}

	info, err := os.Stat(path)
	if err != nil {
		return "unknown"
	}

	s := &Scanner{Language: "auto"}
	exts := s.resolveExtensions(path, info)
	return DetectedLanguage(exts)
}
