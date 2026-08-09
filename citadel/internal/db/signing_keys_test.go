package db

import (
	"context"
	"strings"
	"testing"
)

// TestRegisterKey_ValidatesPublicKeyBeforeTouchingDB confirms RegisterKey
// rejects a malformed public_key hex string during its input-validation
// step, before ever reaching d.Pool.Exec — proven here by using a DB with a
// nil Pool: if RegisterKey tried to use it, this test would panic instead
// of returning a clean validation error.
func TestRegisterKey_ValidatesPublicKeyBeforeTouchingDB(t *testing.T) {
	d := &DB{Pool: nil}

	tests := []struct {
		name  string
		pkHex string
	}{
		{"not hex", "not-valid-hex-zzzz"},
		{"too short", "abcd"},
		{"too long", strings.Repeat("ab", 64)}, // 64 bytes, ed25519 pub key is 32
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := d.RegisterKey(context.Background(), "user-1", "key-1", tt.pkHex)
			if err == nil {
				t.Fatalf("expected error for public_key %q, got nil", tt.pkHex)
			}
			if !strings.Contains(err.Error(), "public_key must be") {
				t.Errorf("unexpected error message: %v", err)
			}
		})
	}
}
