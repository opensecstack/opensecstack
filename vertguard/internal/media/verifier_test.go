package media

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeBinary writes a tiny shell/batch script that prints fixed JSON,
// suitable for cross-platform exec tests.
func fakeBinary(t *testing.T, payload string, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "fake.bat")
		body := "@echo off\r\necho " + payload + "\r\nexit /B " + itoa(exitCode) + "\r\n"
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := filepath.Join(dir, "fake.sh")
	body := "#!/bin/sh\necho '" + payload + "'\nexit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n == 2 {
		return "2"
	}
	return "1"
}

func TestVerify_Success(t *testing.T) {
	bin := fakeBinary(t, `{"has_manifest":true,"signature_valid":false,"signer":null,"claims_count":1,"format":"image/png","errors":[],"warnings":["phase 4.1"],"manifest_summary":{"title":null,"format":null,"instance_id":null,"claim_generator":null}}`, 0)
	v := New(Config{BinaryPath: bin, Timeout: 5 * time.Second, MaxFileSize: 1024})

	res, err := v.Verify(context.Background(), strings.NewReader("hello"), "test.png")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.HasManifest {
		t.Fatal("expected has_manifest=true")
	}
	if res.Format != "image/png" {
		t.Fatalf("format = %q, want image/png", res.Format)
	}
}

func TestVerify_FileTooLarge(t *testing.T) {
	bin := fakeBinary(t, `{}`, 0)
	v := New(Config{BinaryPath: bin, MaxFileSize: 4})
	_, err := v.Verify(context.Background(), strings.NewReader("more than four bytes"), "")
	if err != ErrFileTooLarge {
		t.Fatalf("err = %v, want ErrFileTooLarge", err)
	}
}

func TestVerify_BinaryMissing(t *testing.T) {
	v := New(Config{BinaryPath: "/nonexistent/c2pa-verify"})
	_, err := v.Verify(context.Background(), strings.NewReader("x"), "")
	if err == nil {
		t.Fatal("expected error when binary is missing")
	}
}

// ─── Adversarial coverage stubs (VG-011-c) ──────────────────────────
//
// These cases gate Module 1's adversarial corpus. They are skipped
// today because the test fixtures (signed-then-tampered manifests,
// expired x509 chains, etc.) are not yet checked into the repo.
// They exist so `go test -v` lists them as a coverage marker and
// pipeline reviewers can see what's outstanding.

func TestVerify_TamperedManifest(t *testing.T) {
	t.Skip("test corpus not present yet — see ROADMAP VG-011-c")
}

func TestVerify_ExpiredCert(t *testing.T) {
	t.Skip("test corpus not present yet — see ROADMAP VG-011-c")
}

func TestVerify_UntrustedSigner(t *testing.T) {
	t.Skip("test corpus not present yet — see ROADMAP VG-011-c")
}

func TestVerify_TSATimeout(t *testing.T) {
	t.Skip("test corpus not present yet — see ROADMAP VG-011-c")
}

func TestVerify_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sleep semantics differ on Windows batch scripts")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "slow.sh")
	_ = os.WriteFile(path, []byte("#!/bin/sh\nsleep 5\n"), 0o755)
	v := New(Config{BinaryPath: path, Timeout: 100 * time.Millisecond, MaxFileSize: 1024})
	_, err := v.Verify(context.Background(), strings.NewReader("x"), "")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
