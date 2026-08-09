package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// unreachableDB returns a *DB backed by a lazily-connecting pool aimed at a
// port that actively refuses connections, so calls against it fail fast
// with a real connection error distinct from pgx.ErrNoRows.
func unreachableDB(t *testing.T) *DB {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://citadel:citadel@127.0.0.1:1/citadel?sslmode=disable&connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return &DB{Pool: pool}
}

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

// TestRegisterKey_QueryErrorIsWrapped confirms a real insert failure (DB
// unreachable) surfaces as an error prefixed "db: RegisterKey: insert:"
// rather than being swallowed, once input validation has already passed.
func TestRegisterKey_QueryErrorIsWrapped(t *testing.T) {
	d := unreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	validHexKey := strings.Repeat("ab", 32) // 32 bytes, valid ed25519 pubkey length
	err := d.RegisterKey(ctx, "user-1", "key-1", validHexKey)
	if err == nil {
		t.Fatal("expected error registering against an unreachable database")
	}
	if !strings.Contains(err.Error(), "db: RegisterKey: insert:") {
		t.Errorf("expected wrapped 'db: RegisterKey: insert:' error, got: %v", err)
	}
}

// TestGetActiveKey_QueryErrorIsNotConflatedWithNotFound confirms a genuine
// query/connection failure returns exists=false AND a non-nil error — it
// must not look identical to "no active key" (exists=false, err=nil), which
// would hide a DB outage from GetActiveKey's callers (MARSHAL signature
// gates and the GET /api/v1/keys/{user_id} handler).
func TestGetActiveKey_QueryErrorIsNotConflatedWithNotFound(t *testing.T) {
	d := unreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pub, keyID, exists, err := d.GetActiveKey(ctx, "user-1")
	if err == nil {
		t.Fatal("expected error for a real query failure, got nil")
	}
	if exists {
		t.Error("expected exists=false on error")
	}
	if pub != nil || keyID != "" {
		t.Errorf("expected zero-value results on error, got pub=%v keyID=%q", pub, keyID)
	}
	if !strings.Contains(err.Error(), "db: GetActiveKey: query:") {
		t.Errorf("expected wrapped 'db: GetActiveKey: query:' error, got: %v", err)
	}
}

// TestGetActiveKeyID_QueryErrorIsNotConflatedWithNotFound mirrors the above
// for the metadata-only lookup used by GET /api/v1/keys/{user_id}.
func TestGetActiveKeyID_QueryErrorIsNotConflatedWithNotFound(t *testing.T) {
	d := unreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	keyID, registeredAt, exists, err := d.GetActiveKeyID(ctx, "user-1")
	if err == nil {
		t.Fatal("expected error for a real query failure, got nil")
	}
	if exists {
		t.Error("expected exists=false on error")
	}
	if keyID != "" || !registeredAt.IsZero() {
		t.Errorf("expected zero-value results on error, got keyID=%q registeredAt=%v", keyID, registeredAt)
	}
	if !strings.Contains(err.Error(), "db: GetActiveKeyID: query:") {
		t.Errorf("expected wrapped 'db: GetActiveKeyID: query:' error, got: %v", err)
	}
}

// TestRevokeKey_QueryErrorIsWrapped confirms RevokeKey propagates a real
// update failure instead of silently no-op'ing — a revoke that silently
// fails would leave a compromised/rotated key looking still-active.
func TestRevokeKey_QueryErrorIsWrapped(t *testing.T) {
	d := unreachableDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := d.RevokeKey(ctx, "user-1", "key-1")
	if err == nil {
		t.Fatal("expected error revoking against an unreachable database")
	}
	if !strings.Contains(err.Error(), "db: RevokeKey:") {
		t.Errorf("expected wrapped 'db: RevokeKey:' error, got: %v", err)
	}
}
