// Command vertguard — VertGuard CLI (one-shot scan tool, not the API server).
//
// Subcommands:
//
//	scan          Read input from stdin or --file, run the prompt-injection
//	              engine directly (no HTTP round-trip), print the result.
//	version       Print build version metadata.
//	config-check  Load config, run validation, print the effective config.
//
// Usage examples:
//
//	echo "Ignore previous instructions" | vertguard scan
//	vertguard scan --file payload.txt --format json
//	vertguard version
//	vertguard config-check
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/prompt"
	"github.com/opensecstack/vertguard/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "version":
		runVersion()
	case "config-check":
		runConfigCheck()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `vertguard — VertGuard CLI v%s

Subcommands:
  scan          Scan a prompt for injection attacks
  version       Print build version information
  config-check  Validate and print the effective configuration

Run 'vertguard <subcommand> -h' for subcommand flags.
`, version.Version)
}

// ── scan ─────────────────────────────────────────────────────────────────────

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to input file (defaults to stdin)")
	format := fs.String("format", "human", "Output format: human or json")
	_ = fs.Parse(args)

	// Read input.
	var r io.Reader = os.Stdin
	if *filePath != "" {
		f, err := os.Open(*filePath)
		if err != nil {
			fatalf("open %q: %v", *filePath, err)
		}
		defer f.Close()
		r = f
	}
	input, err := io.ReadAll(r)
	if err != nil {
		fatalf("read input: %v", err)
	}

	// Load config (soft-fail: use defaults on any error).
	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "warning: config load failed (%v); using built-in defaults\n", cfgErr)
		cfg = &config.Config{}
		cfg.Prompt.ApplyDefaults()
	}

	// Build the scan engine — no gRPC, no DB; pure in-process.
	scanner, ruleErr := prompt.NewEngine(prompt.EngineConfig{
		RulePackPath:   cfg.Prompt.RulePackPath,
		CleanThreshold: cfg.Prompt.CleanThreshold,
		BlockThreshold: cfg.Prompt.BlockThreshold,
		MaxInputBytes:  int(cfg.Prompt.MaxInputSize),
	})
	if ruleErr != nil {
		fmt.Fprintf(os.Stderr, "warning: rule pack load failed (%v); using DefaultLibrary\n", ruleErr)
	}

	result, err := scanner.Scan(string(input), "")
	if err != nil {
		fatalf("scan error: %v", err)
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fatalf("encode result: %v", err)
		}
	default:
		fmt.Printf("scan_id:        %s\n", result.ScanID)
		fmt.Printf("classification: %s\n", result.Classification)
		fmt.Printf("confidence:     %.4f\n", result.Confidence)
		fmt.Printf("matches:        %d\n", len(result.Matches))
		fmt.Printf("duration_ms:    %.2f\n", result.DurationMS)
		for i, m := range result.Matches {
			fmt.Printf("  [%d] rule=%s confidence=%.4f\n", i+1, m.PatternID, m.Confidence)
		}
	}

	// Exit non-zero when the prompt is blocked so shell scripts can gate on it.
	if result.Classification == prompt.ClassificationBlocked {
		os.Exit(2)
	}
}

// ── version ───────────────────────────────────────────────────────────────────

func runVersion() {
	info := version.Get()
	fmt.Printf("vertguard %s (commit=%s built=%s)\n",
		info.Version, info.GitCommit, info.BuildDate)
}

// ── config-check ──────────────────────────────────────────────────────────────

func runConfigCheck() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	warns := cfg.WarnIfInsecure()
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "WARNING: %s\n", w)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		fatalf("encode config: %v", err)
	}

	if len(warns) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d insecure setting(s) detected (see warnings above)\n", len(warns))
		os.Exit(3)
	}
	fmt.Fprintln(os.Stderr, "config OK")
}

// ── helpers ───────────────────────────────────────────────────────────────────

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
