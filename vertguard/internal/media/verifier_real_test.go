//go:build c2pa_real

// Real-binary smoke test for the c2pa-verify integration. Gated by
// the `c2pa_real` build tag and the `vertguard_c2pa_path` env var so
// CI environments without a built Rust toolchain are unaffected.
//
// Run with: go test -tags c2pa_real ./internal/media/...
//   VERTGUARD_C2PA_PATH=/path/to/c2pa-verify

package media

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestVerify_RealBinary_NoManifest(t *testing.T) {
	bin := os.Getenv("VERTGUARD_C2PA_PATH")
	if bin == "" {
		t.Skip("VERTGUARD_C2PA_PATH not set")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("binary not present at %q: %v", bin, err)
	}

	v := New(Config{BinaryPath: bin, Timeout: 5 * time.Second, MaxFileSize: 1024})
	res, err := v.Verify(context.Background(), strings.NewReader("hello world, no manifest here"), "noise.bin")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.HasManifest {
		t.Fatal("expected has_manifest=false on random bytes")
	}
	if res.SignatureValid {
		t.Fatal("expected signature_valid=false on random bytes")
	}
}
