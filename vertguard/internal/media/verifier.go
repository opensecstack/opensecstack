// Package media wraps the c2pa-verify Rust binary, exposing a Go API
// that handlers can call. The binary is invoked once per upload with
// a context-bound timeout and a temp-file copy of the upload.
package media

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/uuid"
)

// Trust verdict values surfaced verbatim in the API response.
const (
	TrustStatusTrusted   = "trusted"
	TrustStatusUntrusted = "untrusted"
	TrustStatusRevoked   = "revoked"
	TrustStatusUnsigned  = "unsigned"
)

// ErrUntrusted is returned when the signing cert chain does not
// validate against the configured trust anchors.
var ErrUntrusted = errors.New("media: signing certificate not trusted")

// ErrRevoked is returned when the signing cert appears in the CRL.
var ErrRevoked = errors.New("media: signing certificate revoked")

// Config tunes the verifier.
type Config struct {
	BinaryPath  string
	Timeout     time.Duration
	MaxFileSize int64
	TempDir     string
	// Trust + revocation are optional; nil disables the corresponding
	// check (legacy / migration mode — the result reports "untrusted"
	// when has_manifest=true and TrustStore is nil so operators can
	// still see what would have been rejected).
	TrustStore *TrustStore
	Revocation *RevocationList
}

// Result mirrors the JSON output of c2pa-verify.
type Result struct {
	HasManifest     bool            `json:"has_manifest"`
	SignatureValid  bool            `json:"signature_valid"`
	Signer          *string         `json:"signer"`
	ClaimsCount     uint32          `json:"claims_count"`
	Format          string          `json:"format"`
	Errors          []string        `json:"errors"`
	Warnings        []string        `json:"warnings"`
	ManifestSummary ManifestSummary `json:"manifest_summary"`

	// Trust verdict, populated by Verify after parsing the cert chain.
	// One of TrustStatus* constants.
	TrustStatus      string  `json:"trust_status,omitempty"`
	RevocationReason *string `json:"revocation_reason,omitempty"`

	// SigningCerts carries the parsed cert chain when the c2pa-rs CLI
	// emits it (PEM strings under "signing_certs" or
	// "signing_credential.certs"). Internal use only — not serialised
	// in API responses.
	SigningCerts []string `json:"signing_certs,omitempty"`

	// SigningCredential is the alternative shape some c2pa-rs builds
	// emit. Either field is accepted.
	SigningCredential *signingCredential `json:"signing_credential,omitempty"`
}

// signingCredential mirrors the c2pa-rs `signing_credential` JSON
// shape: a list of PEM-encoded certs (leaf first).
type signingCredential struct {
	Certs []string `json:"certs"`
}

// ManifestSummary mirrors the inner object emitted by the Rust CLI.
type ManifestSummary struct {
	Title          *string `json:"title"`
	Format         *string `json:"format"`
	InstanceID     *string `json:"instance_id"`
	ClaimGenerator *string `json:"claim_generator"`
}

// Verifier shells out to c2pa-verify.
type Verifier struct {
	cfg     Config
	initErr error // set by New() when BinaryPath is missing/non-executable.
}

// maxStderrBytes caps how much of the subprocess stderr we propagate
// in error messages. Prevents config paths / panics from leaking into
// API responses.
const maxStderrBytes = 4 * 1024

// New returns a Verifier and validates that cfg.BinaryPath exists and
// is executable. If validation fails the returned Verifier records
// the error and surfaces it on every Verify call. Callers that want
// a hard startup failure should invoke Validate() on the returned
// instance and abort if it returns non-nil.
func New(cfg Config) *Verifier {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 100 * 1024 * 1024
	}
	if cfg.TempDir == "" {
		cfg.TempDir = os.TempDir()
	}
	v := &Verifier{cfg: cfg}
	v.initErr = checkBinary(cfg.BinaryPath)
	return v
}

// Validate reports any constructor-time error (missing binary, not
// executable, etc.). Returns nil when the verifier is ready to use.
func (v *Verifier) Validate() error { return v.initErr }

// checkBinary stat's the binary and confirms it is a regular file
// with at least one executable bit set on POSIX. On Windows the exec
// bit is not meaningful — file presence is sufficient.
func checkBinary(path string) error {
	if path == "" {
		return errors.New("media: BinaryPath not set")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("media: stat binary %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("media: BinaryPath %q is a directory", path)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0o111 == 0 {
			return fmt.Errorf("media: binary %q is not executable", path)
		}
	}
	return nil
}

// ErrFileTooLarge is returned when the upload exceeds MaxFileSize.
var ErrFileTooLarge = errors.New("media: file exceeds max size")

// Verify writes the reader to a temp file (size-capped), invokes the
// CLI with a context timeout, and parses the JSON output. The temp
// file is removed before returning.
//
// After the subprocess returns, Verify decodes the embedded signing
// cert chain (the c2pa-rs CLI is invoked with --certs so the chain is
// emitted under either `signing_certs` or `signing_credential.certs`).
// The leaf is verified against the configured TrustStore and checked
// against the RevocationList; the verdict is recorded as
// Result.TrustStatus.
func (v *Verifier) Verify(ctx context.Context, r io.Reader, hint string) (*Result, error) {
	if v.initErr != nil {
		return nil, v.initErr
	}

	name := uuid.NewString()
	if hint != "" {
		name += "_" + filepath.Base(hint)
	}
	path := filepath.Join(v.cfg.TempDir, "vertguard-c2pa-"+name)
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}
	// Defers run in LIFO order: register Remove first so Close runs
	// before Remove (the file must be closed before unlink on Windows).
	defer os.Remove(path)
	defer f.Close()

	limited := io.LimitReader(r, v.cfg.MaxFileSize+1)
	n, err := io.Copy(f, limited)
	if err != nil {
		return nil, fmt.Errorf("write temp: %w", err)
	}
	if n > v.cfg.MaxFileSize {
		return nil, ErrFileTooLarge
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithTimeout(ctx, v.cfg.Timeout)
	defer cancel()

	// --certs asks the Rust CLI to embed the signing chain in the
	// JSON output (PEM strings, leaf first). Older builds may ignore
	// the flag; the verifier copes with either shape.
	cmd := exec.CommandContext(runCtx, v.cfg.BinaryPath, // #nosec G204 -- BinaryPath is an operator-configured trusted path (not request-derived); "--input" is the temp file we just created under a uuid name, no user-controlled argv
		"--input", path, "--format", "json", "--certs")
	out, err := cmd.Output()
	if err != nil {
		// Check timeout / cancellation first: exec.CommandContext kills
		// the child when the context expires, which surfaces as either a
		// context error or a signal-terminated ExitError. Either way, the
		// human-readable cause is in runCtx.Err().
		if ctxErr := runCtx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("c2pa-verify timed out after %s: %w",
				v.cfg.Timeout, ctxErr)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := truncateStderr(exitErr.Stderr)
			if stderr == "" {
				return nil, fmt.Errorf("c2pa-verify failed (exit %d)",
					exitErr.ExitCode())
			}
			return nil, fmt.Errorf("c2pa-verify failed (exit %d): %s",
				exitErr.ExitCode(), stderr)
		}
		return nil, fmt.Errorf("c2pa-verify run: %w", err)
	}

	var res Result
	if err := json.Unmarshal(out, &res); err != nil {
		// Include a short snippet of the raw output so operators can
		// diagnose whether the binary emitted a panic, a usage error,
		// or non-JSON text (e.g. an OpenSSL diagnostic on stderr that
		// accidentally leaked to stdout).
		snippet := out
		if len(snippet) > 256 {
			snippet = snippet[:256]
		}
		return nil, fmt.Errorf("parse c2pa-verify output: %w (output: %q)",
			err, snippet)
	}

	v.applyTrustVerdict(&res)
	return &res, nil
}

// applyTrustVerdict fills res.TrustStatus / RevocationReason based on
// the configured trust store, CRL, and the embedded cert chain. The
// function never errors — verdicts are values, not exceptions.
func (v *Verifier) applyTrustVerdict(res *Result) {
	if !res.HasManifest {
		res.TrustStatus = TrustStatusUnsigned
		return
	}

	chain := collectChain(res)
	if len(chain) == 0 {
		// Manifest present but no chain emitted — cannot prove trust.
		res.TrustStatus = TrustStatusUntrusted
		return
	}
	leaf := chain[0]

	if v.cfg.Revocation != nil && v.cfg.Revocation.IsRevoked(leaf) {
		res.TrustStatus = TrustStatusRevoked
		reason := fmt.Sprintf("serial %s on configured CRL", leaf.SerialNumber.String())
		res.RevocationReason = &reason
		return
	}

	if v.cfg.TrustStore == nil {
		res.TrustStatus = TrustStatusUntrusted
		return
	}
	if err := v.cfg.TrustStore.VerifyChain(leaf, chain[1:]); err != nil {
		res.TrustStatus = TrustStatusUntrusted
		return
	}
	res.TrustStatus = TrustStatusTrusted
}

// collectChain pulls PEM (or base64-DER) certs from either of the two
// shapes the c2pa-rs CLI emits and returns the parsed chain
// (leaf first).
func collectChain(res *Result) []*x509.Certificate {
	var pems []string
	pems = append(pems, res.SigningCerts...)
	if res.SigningCredential != nil {
		pems = append(pems, res.SigningCredential.Certs...)
	}
	out := make([]*x509.Certificate, 0, len(pems))
	for _, s := range pems {
		c := parseCertEntry(s)
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

// parseCertEntry handles both PEM-encoded and bare base64-DER cert
// payloads (the latter is what some c2pa-rs versions emit when the
// JSON shape is signing_credential.certs).
func parseCertEntry(s string) *x509.Certificate {
	if s == "" {
		return nil
	}
	if block, _ := pem.Decode([]byte(s)); block != nil && block.Type == "CERTIFICATE" {
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil
		}
		return c
	}
	// Try raw base64-DER.
	if der, err := base64.StdEncoding.DecodeString(s); err == nil {
		if c, err := x509.ParseCertificate(der); err == nil {
			return c
		}
	}
	return nil
}

// truncateStderr returns at most maxStderrBytes of stderr, appending
// a marker if truncated.
func truncateStderr(b []byte) string {
	if len(b) <= maxStderrBytes {
		return string(b)
	}
	return string(b[:maxStderrBytes]) + "...[truncated]"
}
