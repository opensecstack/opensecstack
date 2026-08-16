package handlers

import (
	"path/filepath"
	"testing"

	"github.com/opensecstack/sinauth/internal/keys"
)

// newTestKeyManager builds a keys.Manager backed by a throwaway RSA key
// generated into a temp file, for handler tests (in this package or with the
// integration build tag) that need a real Manager without standing up a full
// server. No build tag on this file — shared by both plain and
// integration-tagged tests in this package.
func newTestKeyManager(t *testing.T, dir string) *keys.Manager {
	t.Helper()
	km := keys.New("test-kid")
	if err := km.LoadOrGenerate(filepath.Join(dir, "signing.pem")); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	return km
}
