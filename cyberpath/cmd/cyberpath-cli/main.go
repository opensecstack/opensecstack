// Command cyberpath-cli — operator + content authoring helper CLI.
//
// v1.0.0: secrets generate, content lint, track import are real.
// v1.0.0: lab run is still a stub.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/cyberpath/internal/content"
)

const usage = `cyberpath-cli — CyberPath operator CLI

Usage:
  cyberpath-cli <command> [subcommand] [flags] [args]

Commands:
  secrets generate     Generate a JWT signing secret
  content lint <path>  Validate track YAML files
  track import <path>  Import tracks into the database
  lab run <slug>       Run a lab locally (v1.0.0)
  help                 Show this help
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(0)
	}

	switch os.Args[1] {
	case "secrets":
		cmdSecrets(os.Args[2:])
	case "content":
		cmdContent(os.Args[2:])
	case "track":
		cmdTrack(os.Args[2:])
	case "lab":
		cmdLab(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

// ── secrets ──────────────────────────────────────────────────────────────────

func cmdSecrets(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: cyberpath-cli secrets generate [--length N]\n")
		os.Exit(2)
	}
	switch args[0] {
	case "generate":
		cmdSecretsGenerate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown secrets subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func cmdSecretsGenerate(args []string) {
	fs := flag.NewFlagSet("secrets generate", flag.ExitOnError)
	length := fs.Int("length", 32, "number of random bytes to generate (default 32 → 64 hex chars)")
	_ = fs.Parse(args)

	if *length <= 0 {
		fmt.Fprintln(os.Stderr, "error: --length must be > 0")
		os.Exit(1)
	}

	buf := make([]byte, *length)
	if _, err := rand.Read(buf); err != nil {
		fmt.Fprintf(os.Stderr, "error: crypto/rand: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(hex.EncodeToString(buf))
}

// ── content ───────────────────────────────────────────────────────────────────

func cmdContent(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: cyberpath-cli content lint <path> [--track <slug>]\n")
		os.Exit(2)
	}
	switch args[0] {
	case "lint":
		cmdContentLint(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown content subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func cmdContentLint(args []string) {
	fs := flag.NewFlagSet("content lint", flag.ExitOnError)
	trackSlug := fs.String("track", "", "lint only this track slug")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: cyberpath-cli content lint <path> [--track <slug>]\n")
		os.Exit(2)
	}
	rootDir := fs.Arg(0)

	var tracks []*content.TrackYAML

	if *trackSlug != "" {
		t, err := content.LoadTrack(rootDir, *trackSlug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %s: %v\n", *trackSlug, err)
			os.Exit(1)
		}
		tracks = []*content.TrackYAML{t}
	} else {
		var err error
		tracks, err = content.LoadAllTracks(rootDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %s: %v\n", rootDir, err)
			os.Exit(1)
		}
	}

	hasErrors := false
	for _, t := range tracks {
		diags := content.ValidateTrackWithRoot(t, rootDir)
		for _, d := range diags {
			sev := "WARN"
			if d.Severity == "error" {
				sev = "ERROR"
				hasErrors = true
			}
			fmt.Printf("[%s] %s: %s\n", sev, d.Path, d.Message)
		}
	}

	if hasErrors {
		os.Exit(1)
	}
	os.Exit(0)
}

// ── track ─────────────────────────────────────────────────────────────────────

func cmdTrack(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: cyberpath-cli track import <path> --db-url <url> [--track <slug>] [--published-by <uuid>]\n")
		os.Exit(2)
	}
	switch args[0] {
	case "import":
		cmdTrackImport(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown track subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func cmdTrackImport(args []string) {
	fs := flag.NewFlagSet("track import", flag.ExitOnError)
	dbURL := fs.String("db-url", "", "PostgreSQL connection string (required)")
	trackSlug := fs.String("track", "", "import only this track slug")
	publishedByStr := fs.String("published-by", "", "UUID of the publishing user (default: system/nil)")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: cyberpath-cli track import <path> --db-url <url> [--track <slug>] [--published-by <uuid>]\n")
		os.Exit(2)
	}
	if *dbURL == "" {
		fmt.Fprintln(os.Stderr, "error: --db-url is required")
		os.Exit(2)
	}

	rootDir := fs.Arg(0)

	publishedBy := uuid.Nil
	if *publishedByStr != "" {
		var err error
		publishedBy, err = uuid.Parse(*publishedByStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: --published-by: invalid UUID: %v\n", err)
			os.Exit(2)
		}
	}

	ctx := context.Background()

	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: connect to database: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	publisher := content.NewPublisher(pool, nil, nil)

	var tracks []*content.TrackYAML

	if *trackSlug != "" {
		t, err := content.LoadTrack(rootDir, *trackSlug)
		if err != nil {
			fmt.Fprintf(os.Stderr, "importing track %s... FAILED: %v\n", *trackSlug, err)
			os.Exit(1)
		}
		tracks = []*content.TrackYAML{t}
	} else {
		tracks, err = content.LoadAllTracks(rootDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: load tracks: %v\n", err)
			os.Exit(1)
		}
	}

	failed := false
	for _, t := range tracks {
		fmt.Printf("importing track %s... ", t.ID)
		if err := publisher.Publish(ctx, t, publishedBy); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			failed = true
		} else {
			fmt.Println("ok")
		}
	}

	if failed {
		os.Exit(1)
	}
	os.Exit(0)
}

// ── lab ───────────────────────────────────────────────────────────────────────

func cmdLab(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: cyberpath-cli lab run <slug>\n")
		os.Exit(2)
	}
	switch args[0] {
	case "run":
		fmt.Println("lab run: not implemented yet (scheduled for v1.0.0)")
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown lab subcommand %q\n", args[0])
		os.Exit(2)
	}
}
