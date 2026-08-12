package scanner

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opensecstack/apiguard/internal/config"
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
// parseSpec — direct unit coverage of the validation-failure branch.
//
// Note: a true end-to-end happy-path test (spawning a real/fake parser
// binary so parseSpec succeeds and the module loop actually runs) was
// deliberately not added here: compiling a helper binary via `go build`
// from within the test process hung for minutes in this sandboxed
// environment (looks like a toolchain/network check), which is exactly the
// kind of flakiness this suite should not depend on. The error-path tests
// below, plus TestRun_TargetValidationFails/TestRun_SpecPathValidationFails/
// TestRun_ParseSpecFailsWithoutParserBinary above, cover Run() up through
// spec parsing without relying on an external process succeeding.
// ---------------------------------------------------------------------------

// A second attempt at a happy-path parseSpec test (a hand-written .bat/shell
// script instead of a `go build`-compiled helper) was also tried and also
// hung indefinitely under `cmd.exe` in this sandboxed environment. Spawning
// external processes to fake the parser binary is not reliable here, so
// parseSpec's success path is left uncovered by this suite rather than
// shipping a test that hangs CI.

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
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
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
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
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
