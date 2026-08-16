package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/opensecstack/cyberpath/internal/content"
)

const sampleTrackRoot = "../../internal/content/testdata"
const sampleTrackSlug = "sample-track"

// ---------------------------------------------------------------------------
// generateSecretHex
// ---------------------------------------------------------------------------

func TestGenerateSecretHex_DefaultLength(t *testing.T) {
	secret, err := generateSecretHex(cryptoRandReaderForTest(), 32)
	if err != nil {
		t.Fatalf("generateSecretHex() error = %v", err)
	}
	if len(secret) != 64 {
		t.Errorf("len(secret) = %d, want 64 (32 bytes hex-encoded)", len(secret))
	}
}

func TestGenerateSecretHex_ZeroOrNegativeLengthRejected(t *testing.T) {
	for _, length := range []int{0, -1, -100} {
		_, err := generateSecretHex(cryptoRandReaderForTest(), length)
		if err == nil {
			t.Errorf("generateSecretHex(length=%d): expected error, got nil", length)
		}
	}
}

func TestGenerateSecretHex_ReaderErrorPropagates(t *testing.T) {
	wantErr := errors.New("boom")
	_, err := generateSecretHex(failingReader{err: wantErr}, 16)
	if err == nil {
		t.Fatal("expected error from failing reader, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
}

func TestGenerateSecretHex_OutputIsDeterministicForFixedInput(t *testing.T) {
	src := bytes.Repeat([]byte{0xAB}, 4)
	secret, err := generateSecretHex(bytes.NewReader(src), 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret != "abababab" {
		t.Errorf("secret = %q, want %q", secret, "abababab")
	}
}

type failingReader struct{ err error }

func (f failingReader) Read(_ []byte) (int, error) { return 0, f.err }

func cryptoRandReaderForTest() *randStub { return &randStub{} }

// randStub is a trivial deterministic io.Reader standing in for
// crypto/rand.Reader in tests that only care about length/error behaviour,
// not cryptographic randomness.
type randStub struct{ n byte }

func (r *randStub) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.n
		r.n++
	}
	return len(p), nil
}

// ---------------------------------------------------------------------------
// parsePublishedBy
// ---------------------------------------------------------------------------

func TestParsePublishedBy_EmptyDefaultsToNil(t *testing.T) {
	got, err := parsePublishedBy("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != uuid.Nil {
		t.Errorf("got %v, want uuid.Nil", got)
	}
}

func TestParsePublishedBy_ValidUUID(t *testing.T) {
	want := uuid.New()
	got, err := parsePublishedBy(want.String())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParsePublishedBy_InvalidUUIDErrors(t *testing.T) {
	_, err := parsePublishedBy("not-a-uuid")
	if err == nil {
		t.Fatal("expected error for invalid UUID, got nil")
	}
}

// ---------------------------------------------------------------------------
// lintTracks
// ---------------------------------------------------------------------------

func TestLintTracks_NonexistentPathIsLoadError(t *testing.T) {
	res := lintTracks(filepath.Join(t.TempDir(), "does-not-exist"), "")
	if res.LoadErr == "" {
		t.Fatal("expected LoadErr for a nonexistent root dir, got none")
	}
	if res.HasErrors {
		t.Error("HasErrors should be false when the failure was a load error")
	}
}

func TestLintTracks_UnknownTrackSlugIsLoadError(t *testing.T) {
	res := lintTracks(sampleTrackRoot, "no-such-track")
	if res.LoadErr == "" {
		t.Fatal("expected LoadErr for an unknown track slug, got none")
	}
	if !strings.Contains(res.LoadErr, "no-such-track") {
		t.Errorf("LoadErr = %q, want it to mention the slug", res.LoadErr)
	}
}

func TestLintTracks_ValidSampleTrackBySlug(t *testing.T) {
	res := lintTracks(sampleTrackRoot, sampleTrackSlug)
	if res.LoadErr != "" {
		t.Fatalf("unexpected LoadErr: %q", res.LoadErr)
	}
	// The fixture may or may not carry warnings; what matters is that
	// loading + validating the known-good fixture never reports a hard
	// validation error.
	if res.HasErrors {
		t.Errorf("HasErrors = true for the sample-track fixture, report:\n%s", res.Report)
	}
}

func TestLintTracks_ValidSampleTrackByScanningAllTracks(t *testing.T) {
	res := lintTracks(sampleTrackRoot, "")
	if res.LoadErr != "" {
		t.Fatalf("unexpected LoadErr: %q", res.LoadErr)
	}
	if res.HasErrors {
		t.Errorf("HasErrors = true when scanning %s, report:\n%s", sampleTrackRoot, res.Report)
	}
}

// ---------------------------------------------------------------------------
// importTracks
// ---------------------------------------------------------------------------

// fakePublisher implements trackPublisher, recording every track it is
// asked to publish and optionally failing on a configured track ID.
type fakePublisher struct {
	published []string
	failIDs   map[string]error
}

func (f *fakePublisher) Publish(_ context.Context, t *content.TrackYAML, _ uuid.UUID) error {
	f.published = append(f.published, t.ID)
	if err, ok := f.failIDs[t.ID]; ok {
		return err
	}
	return nil
}

func TestImportTracks_NonexistentPathIsLoadError(t *testing.T) {
	fp := &fakePublisher{}
	res := importTracks(context.Background(), fp, filepath.Join(t.TempDir(), "nope"), "", uuid.Nil)
	if res.LoadErr == "" {
		t.Fatal("expected LoadErr for a nonexistent root dir, got none")
	}
	if len(fp.published) != 0 {
		t.Errorf("expected no Publish calls on load failure, got %d", len(fp.published))
	}
}

func TestImportTracks_PublishesLoadedTrackAndReportsOK(t *testing.T) {
	fp := &fakePublisher{}
	res := importTracks(context.Background(), fp, sampleTrackRoot, sampleTrackSlug, uuid.Nil)
	if res.LoadErr != "" {
		t.Fatalf("unexpected LoadErr: %q", res.LoadErr)
	}
	if res.Failed {
		t.Errorf("Failed = true, report:\n%s", res.Report)
	}
	if len(fp.published) != 1 || fp.published[0] != sampleTrackSlug {
		t.Errorf("published = %v, want exactly [%q]", fp.published, sampleTrackSlug)
	}
	if !strings.Contains(res.Report, "ok") {
		t.Errorf("report = %q, want it to contain %q", res.Report, "ok")
	}
}

func TestImportTracks_PublishErrorIsReportedAsFailed(t *testing.T) {
	wantErr := errors.New("db unavailable")
	fp := &fakePublisher{failIDs: map[string]error{sampleTrackSlug: wantErr}}
	res := importTracks(context.Background(), fp, sampleTrackRoot, sampleTrackSlug, uuid.Nil)
	if res.LoadErr != "" {
		t.Fatalf("unexpected LoadErr: %q", res.LoadErr)
	}
	if !res.Failed {
		t.Fatal("expected Failed = true when Publish errors")
	}
	if !strings.Contains(res.Report, "FAILED") || !strings.Contains(res.Report, "db unavailable") {
		t.Errorf("report = %q, want it to mention FAILED and the error", res.Report)
	}
}

func TestImportTracks_UsesGivenPublishedBy(t *testing.T) {
	fp := &fakePublisher{}
	var gotPublishedBy uuid.UUID
	wrapper := publishFunc(func(ctx context.Context, tr *content.TrackYAML, by uuid.UUID) error {
		gotPublishedBy = by
		return fp.Publish(ctx, tr, by)
	})
	want := uuid.New()
	res := importTracks(context.Background(), wrapper, sampleTrackRoot, sampleTrackSlug, want)
	if res.Failed {
		t.Fatalf("unexpected failure: %s", res.Report)
	}
	if gotPublishedBy != want {
		t.Errorf("publishedBy = %v, want %v", gotPublishedBy, want)
	}
}

// publishFunc adapts a plain function to the trackPublisher interface.
type publishFunc func(ctx context.Context, t *content.TrackYAML, publishedBy uuid.UUID) error

func (f publishFunc) Publish(ctx context.Context, t *content.TrackYAML, publishedBy uuid.UUID) error {
	return f(ctx, t, publishedBy)
}

// ---------------------------------------------------------------------------
// main() end-to-end, via subprocess
//
// main() and the cmdX dispatcher wrappers call os.Exit directly, which
// would kill the `go test` process if invoked in-process. The standard
// pattern (also used by Go's own os/exec package tests) is to re-exec the
// test binary itself as a subprocess with a sentinel env var, so the real
// os.Exit runs in a disposable child process and only its exit code +
// output are observed here.
// ---------------------------------------------------------------------------

// TestHelperProcess is not a real test: it is only ever invoked by runCLI,
// as a subprocess with GO_WANT_HELPER_PROCESS=1 set. It reconstructs the
// intended cyberpath-cli argv (everything after "--" in the subprocess's
// own os.Args, which carries both `go test` flags and our CLI args) and
// calls the real main().
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	os.Args = append([]string{"cyberpath-cli"}, args...)
	main()
}

// runCLI runs cmd/cyberpath-cli's main() in a subprocess with the given
// argv (as os.Args[1:] would appear), returning combined stdout+stderr and
// the process exit code.
func runCLI(t *testing.T, args ...string) (string, int) {
	t.Helper()
	testFlags := []string{"-test.run=^TestHelperProcess$"}
	// Forward -test.gocoverdir so the child's execution of main() (and
	// everything it calls) contributes to this package's coverage
	// profile. GOCOVERDIR being set in the environment is not, by
	// itself, enough for a *test* binary — unlike a plain `go build
	// -cover` binary, the testing package only writes coverage data
	// when explicitly told where via this flag.
	if dir := os.Getenv("GOCOVERDIR"); dir != "" {
		testFlags = append(testFlags, "-test.gocoverdir="+dir)
	}
	cmdArgs := append(testFlags, "--")
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.CommandContext(context.Background(), os.Args[0], cmdArgs...)
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("runCLI(%v): %v\noutput:\n%s", args, err, out)
		}
	}
	return string(out), exitCode
}

func TestMain_NoArgsPrintsUsageAndExitsZero(t *testing.T) {
	out, code := runCLI(t)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "cyberpath-cli") {
		t.Errorf("output = %q, want it to contain the usage banner", out)
	}
}

func TestMain_HelpPrintsUsageAndExitsZero(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		out, code := runCLI(t, arg)
		if code != 0 {
			t.Errorf("%s: exit code = %d, want 0", arg, code)
		}
		if !strings.Contains(out, "Usage:") {
			t.Errorf("%s: output = %q, want it to contain Usage:", arg, out)
		}
	}
}

func TestMain_UnknownCommandExits2(t *testing.T) {
	out, code := runCLI(t, "bogus")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(out, `unknown command "bogus"`) {
		t.Errorf("output = %q, want it to mention the unknown command", out)
	}
}

func TestMain_SecretsNoSubcommandExits2(t *testing.T) {
	_, code := runCLI(t, "secrets")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestMain_SecretsUnknownSubcommandExits2(t *testing.T) {
	_, code := runCLI(t, "secrets", "bogus")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

// wantHexPrefix asserts out begins with exactly wantLen lowercase hex
// characters. cmdSecretsGenerate (like the original code it preserves)
// never calls os.Exit on its success path — it returns and lets main()
// return normally — so under our subprocess-of-a-coverage-instrumented-
// test-binary harness, the go test framework's own "PASS\ncoverage: ...%
// of statements" trailer is appended to stdout right after the secret.
// That trailer is a test-harness artifact, not CLI output, so we only
// check the expected hex prefix rather than the whole string.
func wantHexPrefix(t *testing.T, out string, wantLen int) {
	t.Helper()
	if len(out) < wantLen {
		t.Fatalf("output = %q (len %d), want at least %d leading hex chars", out, len(out), wantLen)
	}
	prefix := out[:wantLen]
	for _, c := range prefix {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("output prefix = %q, contains non-hex character %q", prefix, c)
		}
	}
}

func TestMain_SecretsGenerateDefaultLength(t *testing.T) {
	out, code := runCLI(t, "secrets", "generate")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	wantHexPrefix(t, out, 64)
}

func TestMain_SecretsGenerateCustomLength(t *testing.T) {
	out, code := runCLI(t, "secrets", "generate", "--length", "8")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	wantHexPrefix(t, out, 16)
}

func TestMain_SecretsGenerateInvalidLengthExits1(t *testing.T) {
	out, code := runCLI(t, "secrets", "generate", "--length", "0")
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(out, "--length must be > 0") {
		t.Errorf("output = %q, want it to mention the length requirement", out)
	}
}

func TestMain_ContentNoArgsExits2(t *testing.T) {
	_, code := runCLI(t, "content")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestMain_ContentUnknownSubcommandExits2(t *testing.T) {
	_, code := runCLI(t, "content", "bogus")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestMain_ContentLintNoPathExits2(t *testing.T) {
	_, code := runCLI(t, "content", "lint")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestMain_ContentLintValidTrackExitsZero(t *testing.T) {
	out, code := runCLI(t, "content", "lint", sampleTrackRoot, "--track", sampleTrackSlug)
	if code != 0 {
		t.Errorf("exit code = %d, want 0, output:\n%s", code, out)
	}
}

func TestMain_ContentLintNonexistentPathExits1(t *testing.T) {
	out, code := runCLI(t, "content", "lint", filepath.Join(t.TempDir(), "nope"))
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(out, "[ERROR]") {
		t.Errorf("output = %q, want it to contain [ERROR]", out)
	}
}

func TestMain_TrackNoArgsExits2(t *testing.T) {
	_, code := runCLI(t, "track")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestMain_TrackUnknownSubcommandExits2(t *testing.T) {
	_, code := runCLI(t, "track", "bogus")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestMain_TrackImportNoPathExits2(t *testing.T) {
	_, code := runCLI(t, "track", "import")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestMain_TrackImportMissingDBURLExits2(t *testing.T) {
	out, code := runCLI(t, "track", "import", sampleTrackRoot)
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(out, "--db-url is required") {
		t.Errorf("output = %q, want it to mention --db-url", out)
	}
}

func TestMain_TrackImportInvalidPublishedByExits2(t *testing.T) {
	out, code := runCLI(t, "track", "import", sampleTrackRoot, "--db-url", "postgres://x", "--published-by", "not-a-uuid")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(out, "invalid UUID") {
		t.Errorf("output = %q, want it to mention invalid UUID", out)
	}
}

func TestMain_LabNoArgsExits2(t *testing.T) {
	_, code := runCLI(t, "lab")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}

func TestMain_LabRunStubExitsZero(t *testing.T) {
	out, code := runCLI(t, "lab", "run", "some-slug")
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "not implemented yet") {
		t.Errorf("output = %q, want it to mention the stub message", out)
	}
}

func TestMain_LabUnknownSubcommandExits2(t *testing.T) {
	_, code := runCLI(t, "lab", "bogus")
	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}
