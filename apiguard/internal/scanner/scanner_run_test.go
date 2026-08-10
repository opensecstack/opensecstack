package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/domain"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Run — early validation failure paths (no external parser binary needed)
// ---------------------------------------------------------------------------

func TestRun_TargetValidationFails(t *testing.T) {
	s := New(&config.ScannerConfig{MaxSpecSize: 10, Timeout: time.Second}, zerolog.Nop())
	_, err := s.Run(context.Background(), ScanRequest{
		SpecPath: "does-not-matter.json",
		Target:   "http://192.168.1.50/api", // private range, allowInternal=false
	})
	if err == nil {
		t.Fatal("expected error for SSRF-blocked target URL")
	}
}

func TestRun_SpecPathValidationFails(t *testing.T) {
	dir := t.TempDir()
	s := New(&config.ScannerConfig{MaxSpecSize: 10, Timeout: time.Second}, zerolog.Nop())
	_, err := s.Run(context.Background(), ScanRequest{
		SpecPath:      filepath.Join(dir, "nonexistent-spec.json"),
		Target:        "http://127.0.0.1/api",
		AllowInternal: true,
	})
	if err == nil {
		t.Fatal("expected error for missing spec file")
	}
}

func TestRun_ParseSpecFailsWithoutParserBinary(t *testing.T) {
	// No apiguard-parser binary is installed anywhere on PATH in this test
	// environment, so Run must surface a "spec parsing failed" error rather
	// than panicking or hanging.
	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(specPath, []byte(`{"openapi":"3.0.0"}`), 0o644); err != nil {
		t.Fatalf("failed to write spec file: %v", err)
	}

	// Guarantee no leftover APIGUARD_PARSER_BIN from the environment points at
	// a real binary, and that a bogus bare name can't accidentally resolve.
	t.Setenv("APIGUARD_PARSER_BIN", "apiguard-parser-definitely-not-installed-xyz")

	s := New(&config.ScannerConfig{MaxSpecSize: 10, Timeout: time.Second}, zerolog.Nop())
	_, err := s.Run(context.Background(), ScanRequest{
		SpecPath:      specPath,
		Target:        "http://127.0.0.1/api",
		AllowInternal: true,
	})
	if err == nil {
		t.Fatal("expected error when parser binary cannot be executed")
	}
}

// ---------------------------------------------------------------------------
// Run — full happy path, using a fake compiled "apiguard-parser" so parseSpec
// succeeds via the native (non-Rust) path, and a local httptest server as the
// scan target so module HTTP calls resolve locally instead of hitting the
// network.
// ---------------------------------------------------------------------------

// buildFakeParser compiles a tiny stdlib-only Go program that writes a fixed,
// valid IR JSON document to whatever --output path it's given, and returns
// the directory it was placed in (named so bare "apiguard-parser" PATH
// lookup resolves to it). It skips the test if the go toolchain isn't usable
// from within the test process (e.g. a locked-down sandbox).
func buildFakeParser(t *testing.T) string {
	t.Helper()

	binDir := t.TempDir()
	srcDir := t.TempDir()
	srcFile := filepath.Join(srcDir, "main.go")

	const src = `package main

import "os"

func main() {
	out := ""
	for i, a := range os.Args {
		if a == "--output" && i+1 < len(os.Args) {
			out = os.Args[i+1]
		}
	}
	if out == "" {
		os.Exit(1)
	}
	data := ` + "`" + `{"endpoints":[{"path":"/items/{id}","method":"GET","parameters":[{"name":"id","location":"path","required":true}],"responses":{},"security":["bearer"],"tags":[],"x_apiguard":{}}],"auth_schemes":[{"name":"bearer","scheme_type":"http","header_name":"Authorization"}],"metadata":{"base_url":"http://test","api_version":"1.0","schema_hash":"deadbeef"}}` + "`" + `
	if err := os.WriteFile(out, []byte(data), 0o644); err != nil {
		os.Exit(1)
	}
}
`
	if err := os.WriteFile(srcFile, []byte(src), 0o644); err != nil {
		t.Fatalf("failed to write fake parser source: %v", err)
	}

	binName := "apiguard-parser"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(binDir, binName)

	cmd := exec.Command("go", "build", "-o", binPath, srcFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("skipping: could not build fake parser binary (go toolchain unavailable in test env): %v\n%s", err, out)
	}

	return binDir
}

func TestRun_FullHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full Run() integration test in -short mode")
	}

	binDir := buildFakeParser(t)

	// Prepend the fake-parser directory to PATH so the bare "apiguard-parser"
	// name (the default parserBin in parseSpec) resolves to it.
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)
	// Make sure APIGUARD_PARSER_BIN doesn't override our fake binary and that
	// the Rust testgen binary genuinely isn't found, so Run exercises the Go
	// native testgen fallback.
	t.Setenv("APIGUARD_PARSER_BIN", "")
	t.Setenv("APIGUARD_TESTGEN_BIN", "apiguard-testgen-definitely-not-installed-xyz")

	// Local target server: respond to everything so module HTTP calls succeed
	// without needing network access.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"123","ok":true}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	specPath := filepath.Join(dir, "spec.json")
	// Content is irrelevant: the fake parser ignores --input and always
	// writes the same fixed IR, but validateSpecPath still needs a real,
	// readable, regular file to open/stat.
	if err := os.WriteFile(specPath, []byte(`{"openapi":"3.0.0"}`), 0o644); err != nil {
		t.Fatalf("failed to write spec file: %v", err)
	}

	s := New(&config.ScannerConfig{MaxSpecSize: 10, Timeout: 30 * time.Second}, zerolog.Nop())

	req := ScanRequest{
		SpecPath:      specPath,
		Target:        srv.URL,
		AllowInternal: true,
		TLSSkipVerify: false,
		Auth: AuthConfig{
			Token: "test-token",
			Type:  "bearer",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := s.Run(ctx, req)
	if err != nil {
		t.Fatalf("expected Run to complete successfully, got error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil scan result")
	}
	if result.Status != domain.ScanStatusCompleted {
		t.Errorf("expected scan status completed, got %q", result.Status)
	}
	if result.Target != srv.URL {
		t.Errorf("expected result target %q, got %q", srv.URL, result.Target)
	}
	if result.SpecHash == "" {
		t.Error("expected non-empty spec hash")
	}
	if result.Findings == nil {
		t.Error("expected non-nil (possibly empty) findings slice")
	}
}

// ---------------------------------------------------------------------------
// parseSpec — direct unit coverage of the validation-failure branch.
// ---------------------------------------------------------------------------

func TestParseSpec_InvalidParserBinRejected(t *testing.T) {
	t.Setenv("APIGUARD_PARSER_BIN", "bad;parser")

	s := New(&config.ScannerConfig{MaxSpecSize: 10, Timeout: time.Second}, zerolog.Nop())
	_, err := s.parseSpec(context.Background(), "irrelevant.json")
	if err == nil {
		t.Fatal("expected error for parser binary containing shell metacharacters")
	}
}

func TestParseSpec_ExecutionFailureSurfaced(t *testing.T) {
	t.Setenv("APIGUARD_PARSER_BIN", "apiguard-parser-definitely-not-installed-xyz")

	s := New(&config.ScannerConfig{MaxSpecSize: 10, Timeout: time.Second}, zerolog.Nop())
	_, err := s.parseSpec(context.Background(), "irrelevant.json")
	if err == nil {
		t.Fatal("expected error when the parser binary cannot be found/executed")
	}
}

// ---------------------------------------------------------------------------
// writeIRToTempFile
// ---------------------------------------------------------------------------

func TestWriteIRToTempFile_Success(t *testing.T) {
	s := New(&config.ScannerConfig{MaxSpecSize: 10}, zerolog.Nop())
	spec := &ParsedSpec{
		Metadata: ParsedMetadata{BaseURL: "http://x", APIVersion: "1.0", SchemaHash: "abc"},
	}
	path, err := s.writeIRToTempFile(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected temp IR file to be readable: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty IR file contents")
	}
}

func TestWriteIRToTempFile_WriteFailure(t *testing.T) {
	// Point both TMP and TEMP (Windows) / TMPDIR (Unix) at a directory that
	// does not exist, forcing os.WriteFile inside writeIRToTempFile to fail.
	badDir := filepath.Join(t.TempDir(), "does-not-exist", "nested")
	t.Setenv("TMPDIR", badDir)
	t.Setenv("TMP", badDir)
	t.Setenv("TEMP", badDir)

	s := New(&config.ScannerConfig{MaxSpecSize: 10}, zerolog.Nop())
	spec := &ParsedSpec{Metadata: ParsedMetadata{SchemaHash: "abc"}}
	_, err := s.writeIRToTempFile(spec)
	if err == nil {
		t.Fatal("expected error writing IR temp file to a nonexistent directory")
	}
}

// ---------------------------------------------------------------------------
// CreatePinnedTransport — exercise the DialContext closure itself, not just
// the struct it returns.
// ---------------------------------------------------------------------------

func TestCreatePinnedTransport_DialContext_PinsToValidatedIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to split listener address: %v", err)
	}

	// A hostname that will never resolve via real DNS; the pinned transport
	// must redirect connections for this host to the validated IP (loopback)
	// instead of attempting a real DNS lookup.
	const fakeHost = "pinned-host.invalid.test"
	transport := CreatePinnedTransport(fakeHost, []net.IP{net.ParseIP("127.0.0.1")}, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := transport.DialContext(ctx, "tcp", net.JoinHostPort(fakeHost, port))
	if err != nil {
		t.Fatalf("expected DialContext to succeed via pinned IP, got error: %v", err)
	}
	_ = conn.Close()
}

func TestCreatePinnedTransport_DialContext_NonMatchingHostDialsDirect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	// validatedHost does not match the address being dialed, so the pin
	// should NOT apply and the dial should proceed against the real address
	// (loopback), which must still succeed.
	transport := CreatePinnedTransport("some-other-host", []net.IP{net.ParseIP("10.99.99.99")}, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := transport.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("expected direct dial to succeed for non-matching host, got error: %v", err)
	}
	_ = conn.Close()
}

func TestCreatePinnedTransport_DialContext_MalformedAddrErrors(t *testing.T) {
	transport := CreatePinnedTransport("host", nil, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := transport.DialContext(ctx, "tcp", "no-port-here")
	if err == nil {
		t.Fatal("expected error for address missing a port")
	}
}

// ---------------------------------------------------------------------------
// validateParserBin — additional branches
// ---------------------------------------------------------------------------

func TestValidateParserBin_ForwardSlashRelativeRejected(t *testing.T) {
	if err := validateParserBin("sub/parser"); err == nil {
		t.Fatal("expected error for relative path containing a forward slash")
	}
}

func TestValidateParserBin_EmptyStringAllowedAsBareName(t *testing.T) {
	// An empty string contains no metacharacters, is not absolute, and
	// contains no separators, so it falls through to the bare-name/PATH case.
	if err := validateParserBin(""); err != nil {
		t.Errorf("unexpected error for empty parser bin string: %v", err)
	}
}
