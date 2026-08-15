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
	"io"
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

	secret, err := generateSecretHex(rand.Reader, *length)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(secret)
}

// generateSecretHex reads length random bytes from randReader and returns
// their hex encoding. Pure aside from the injected reader, so tests can
// exercise both the happy path and error propagation without depending on
// the global crypto/rand.Reader.
func generateSecretHex(randReader io.Reader, length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("--length must be > 0")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(buf), nil
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
	// The path is parsed as a leading positional argument before flag
	// parsing, not left to flag.FlagSet.Parse — Go's flag package stops
	// parsing at the first non-flag argument, so with the documented
	// invocation order (`content lint <path> [--track <slug>]`) a
	// FlagSet.Parse(args) call would treat <path> as the parse-stop point
	// and silently ignore --track entirely.
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: cyberpath-cli content lint <path> [--track <slug>]\n")
		os.Exit(2)
	}
	rootDir := args[0]

	fs := flag.NewFlagSet("content lint", flag.ExitOnError)
	trackSlug := fs.String("track", "", "lint only this track slug")
	_ = fs.Parse(args[1:])

	res := lintTracks(rootDir, *trackSlug)
	if res.LoadErr != "" {
		fmt.Fprint(os.Stderr, res.LoadErr)
		os.Exit(1)
	}
	fmt.Print(res.Report)
	if res.HasErrors {
		os.Exit(1)
	}
	os.Exit(0)
}

// lintResult is the outcome of lintTracks: LoadErr is non-empty only when
// loading the track(s) from disk failed (destined for stderr, exit 1);
// otherwise Report holds the rendered [WARN]/[ERROR] diagnostic lines
// (destined for stdout) and HasErrors reports whether any diagnostic was
// "error" severity (exit 1) as opposed to only warnings (exit 0).
type lintResult struct {
	LoadErr   string
	Report    string
	HasErrors bool
}

// lintTracks loads either a single track (trackSlug non-empty) or every
// track under rootDir, validates each, and renders a report identical to
// the CLI's original inline output — extracted from cmdContentLint so the
// loading/validation/reporting logic can be tested without going through
// os.Exit.
func lintTracks(rootDir, trackSlug string) lintResult {
	var tracks []*content.TrackYAML

	if trackSlug != "" {
		t, err := content.LoadTrack(rootDir, trackSlug)
		if err != nil {
			return lintResult{LoadErr: fmt.Sprintf("[ERROR] %s: %v\n", trackSlug, err)}
		}
		tracks = []*content.TrackYAML{t}
	} else {
		var err error
		tracks, err = content.LoadAllTracks(rootDir)
		if err != nil {
			return lintResult{LoadErr: fmt.Sprintf("[ERROR] %s: %v\n", rootDir, err)}
		}
	}

	var out string
	hasErrors := false
	for _, t := range tracks {
		diags := content.ValidateTrackWithRoot(t, rootDir)
		for _, d := range diags {
			sev := "WARN"
			if d.Severity == "error" {
				sev = "ERROR"
				hasErrors = true
			}
			out += fmt.Sprintf("[%s] %s: %s\n", sev, d.Path, d.Message)
		}
	}

	return lintResult{Report: out, HasErrors: hasErrors}
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
	// See cmdContentLint for why the path is peeled off as a leading
	// positional argument before flag parsing rather than relying on
	// flag.FlagSet.Parse to find it via NArg()/Arg(0): with the documented
	// invocation order (`track import <path> --db-url <url> ...`),
	// FlagSet.Parse(args) stops at the first non-flag argument (<path>)
	// and never sees --db-url/--track/--published-by at all.
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: cyberpath-cli track import <path> --db-url <url> [--track <slug>] [--published-by <uuid>]\n")
		os.Exit(2)
	}
	rootDir := args[0]

	fs := flag.NewFlagSet("track import", flag.ExitOnError)
	dbURL := fs.String("db-url", "", "PostgreSQL connection string (required)")
	trackSlug := fs.String("track", "", "import only this track slug")
	publishedByStr := fs.String("published-by", "", "UUID of the publishing user (default: system/nil)")
	_ = fs.Parse(args[1:])

	if *dbURL == "" {
		fmt.Fprintln(os.Stderr, "error: --db-url is required")
		os.Exit(2)
	}

	publishedBy, err := parsePublishedBy(*publishedByStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --published-by: invalid UUID: %v\n", err)
		os.Exit(2)
	}

	ctx := context.Background()

	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: connect to database: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	publisher := content.NewPublisher(pool, nil, nil)

	res := importTracks(ctx, publisher, rootDir, *trackSlug, publishedBy)
	if res.LoadErr != "" {
		fmt.Fprint(os.Stderr, res.LoadErr)
		os.Exit(1)
	}
	fmt.Print(res.Report)
	if res.Failed {
		os.Exit(1)
	}
	os.Exit(0)
}

// parsePublishedBy parses the --published-by flag value, defaulting to
// uuid.Nil (the "system" publisher) when the flag is unset.
func parsePublishedBy(s string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, nil
	}
	return uuid.Parse(s)
}

// trackPublisher is the narrow slice of *content.Publisher that
// importTracks needs, extracted here (not in internal/content) so tests
// can supply a fake without a live database connection.
type trackPublisher interface {
	Publish(ctx context.Context, t *content.TrackYAML, publishedBy uuid.UUID) error
}

// importResult is the outcome of importTracks: LoadErr is non-empty only
// when loading the track(s) from disk failed (destined for stderr, exit 1,
// before any Publish call is attempted); otherwise Report holds the
// per-track "importing track X... ok/FAILED" progress lines (destined for
// stdout) and Failed reports whether any individual track's Publish call
// returned an error.
type importResult struct {
	LoadErr string
	Report  string
	Failed  bool
}

// importTracks loads either a single track (trackSlug non-empty) or every
// track under rootDir and publishes each via pub, rendering a progress
// report identical to the CLI's original inline output — extracted from
// cmdTrackImport so the load/publish/reporting logic can be tested with a
// fake trackPublisher instead of a live database connection.
func importTracks(ctx context.Context, pub trackPublisher, rootDir, trackSlug string, publishedBy uuid.UUID) importResult {
	var tracks []*content.TrackYAML

	if trackSlug != "" {
		t, err := content.LoadTrack(rootDir, trackSlug)
		if err != nil {
			return importResult{LoadErr: fmt.Sprintf("importing track %s... FAILED: %v\n", trackSlug, err)}
		}
		tracks = []*content.TrackYAML{t}
	} else {
		var err error
		tracks, err = content.LoadAllTracks(rootDir)
		if err != nil {
			return importResult{LoadErr: fmt.Sprintf("error: load tracks: %v\n", err)}
		}
	}

	var out string
	failed := false
	for _, t := range tracks {
		out += fmt.Sprintf("importing track %s... ", t.ID)
		if err := pub.Publish(ctx, t, publishedBy); err != nil {
			out += fmt.Sprintf("FAILED: %v\n", err)
			failed = true
		} else {
			out += "ok\n"
		}
	}

	return importResult{Report: out, Failed: failed}
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
