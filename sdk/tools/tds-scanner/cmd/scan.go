package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/opensecstack/tds-scanner/internal/report"
	"github.com/opensecstack/tds-scanner/internal/scanner"
)

var (
	scanLang     string
	scanChecks   string
	scanExitCode bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [flags] <target>",
	Short: "Scan a file, directory, or project for TDS compliance issues",
	Long: `Scans a file, directory, or Go/Python/Rust project for TDS compliance issues.

TDS (Trust, Dependency, Security) checks cover:
  - Hardcoded credentials and weak authentication patterns (TDS-AUTH)
  - TLS verification bypass and weak transport patterns (TDS-TLS)
  - Missing retry/backoff patterns in HTTP calls (TDS-RETRY)
  - Secrets and private key material in source files (TDS-SECRET)
  - Missing security headers in HTTP client code (TDS-HDR)`,
	Example: `  tds-scanner scan ./sdk/go
  tds-scanner scan --lang python ./sdk/python
  tds-scanner scan --format json -o results.json ./
  tds-scanner scan --checks TDS-AUTH-001,TDS-TLS-001 --severity critical ./`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanLang, "lang", "auto",
		`Language hint: go, python, rust, or auto (default: auto)`)
	scanCmd.Flags().StringVar(&scanChecks, "checks", "",
		"Comma-separated check IDs to run (default: all)")
	scanCmd.Flags().BoolVar(&scanExitCode, "exit-code", true,
		"Exit with code 1 if any findings at or above the --severity threshold are found")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]

	// Resolve and validate the target path.
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("invalid target path %q: %w", target, err)
	}

	// Build check ID list from the --checks flag.
	var checkIDs []string
	if scanChecks != "" {
		for _, id := range strings.Split(scanChecks, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				checkIDs = append(checkIDs, id)
			}
		}
	}

	s := &scanner.Scanner{
		MinSeverity: flagSeverity,
		Checks:      checkIDs,
		Language:    scanLang,
	}

	findings, checksRun, err := s.ScanPath(absTarget)
	if err != nil {
		return err
	}

	// Determine the detected language for the report.
	lang := scanLang
	if lang == "auto" {
		lang = scanner.DetectLanguageFromPath(absTarget, scanLang)
	}

	// Determine pass/fail result.
	result := "pass"
	if len(findings) > 0 {
		result = "fail"
	}

	// Resolve output writer.
	var w io.Writer = os.Stdout
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("cannot open output file %q: %w", flagOutput, err)
		}
		defer f.Close()
		w = f
	}

	// Render the report.
	switch strings.ToLower(flagFormat) {
	case "json":
		if err := report.WriteJSON(w, target, lang, checksRun, findings, result); err != nil {
			return err
		}
	default:
		if err := report.WriteText(w, target, lang, checksRun, findings, flagSeverity, result); err != nil {
			return err
		}
	}

	// Honour --exit-code.
	if scanExitCode && result == "fail" {
		// Cobra will not print "exit status 1" — we use os.Exit directly so
		// that the report has already been flushed.
		os.Exit(1)
	}

	return nil
}

