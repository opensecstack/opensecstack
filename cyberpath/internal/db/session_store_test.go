//go:build integration

// Integration tests for DBSessionStore against the `sessions` table.
// Requires CYBERPATH_TEST_DB_URL; skipped otherwise.
package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/cyberpath/internal/auth"
)

func sessionFixtureUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()

	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "sess-"+tenantID.String()[:8], "session-test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		userID, tenantID, userID.String()+"@test.local"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return userID
}

func TestDBSessionStore_CreateGetValidate(t *testing.T) {
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	userID := sessionFixtureUser(t, ctx, pool)
	store := NewDBSessionStore(pool)

	sessionID := auth.NewSessionID()
	refreshTok := "raw-refresh-token-" + sessionID
	sess := auth.Session{
		ID:               sessionID,
		UserID:           userID.String(),
		RefreshTokenHash: auth.HashRefreshToken(refreshTok),
		IssuedAt:         time.Now(),
		ExpiresAt:        time.Now().Add(1 * time.Hour),
		IPAddress:        "203.0.113.5",
		UserAgent:        "test-agent/1.0",
	}
	if err := store.Create(sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.GetByRefreshToken(refreshTok)
	if err != nil {
		t.Fatalf("GetByRefreshToken: %v", err)
	}
	if got.ID != sessionID {
		t.Fatalf("GetByRefreshToken: id = %q, want %q", got.ID, sessionID)
	}
	if got.IPAddress != "203.0.113.5" || got.UserAgent != "test-agent/1.0" {
		t.Fatalf("GetByRefreshToken: unexpected ip/ua: %+v", got)
	}

	valid, err := store.Validate(refreshTok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if valid.ID != sessionID {
		t.Fatalf("Validate: id = %q, want %q", valid.ID, sessionID)
	}
}

func TestDBSessionStore_Create_EmptyFields(t *testing.T) {
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	store := NewDBSessionStore(pool)

	if err := store.Create(auth.Session{ID: "", RefreshTokenHash: "x"}); err == nil {
		t.Fatal("Create: expected error for empty ID, got nil")
	}
	if err := store.Create(auth.Session{ID: "id-only", RefreshTokenHash: ""}); err == nil {
		t.Fatal("Create: expected error for empty RefreshTokenHash, got nil")
	}
}

func TestDBSessionStore_GetByRefreshToken_NotFound(t *testing.T) {
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	store := NewDBSessionStore(pool)

	_, err = store.GetByRefreshToken("token-that-does-not-exist-" + uuid.New().String())
	if err != auth.ErrSessionNotFound {
		t.Fatalf("GetByRefreshToken: err = %v, want auth.ErrSessionNotFound", err)
	}
}

func TestDBSessionStore_RevokeAndValidate(t *testing.T) {
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	userID := sessionFixtureUser(t, ctx, pool)
	store := NewDBSessionStore(pool)

	sessionID := auth.NewSessionID()
	refreshTok := "revoke-me-" + sessionID
	sess := auth.Session{
		ID:               sessionID,
		UserID:           userID.String(),
		RefreshTokenHash: auth.HashRefreshToken(refreshTok),
		IssuedAt:         time.Now(),
		ExpiresAt:        time.Now().Add(1 * time.Hour),
	}
	if err := store.Create(sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.Revoke(sessionID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, err := store.Validate(refreshTok); err != auth.ErrSessionNotFound {
		t.Fatalf("Validate after revoke: err = %v, want auth.ErrSessionNotFound", err)
	}

	// Revoke is idempotent — revoking again must not error.
	if err := store.Revoke(sessionID); err != nil {
		t.Fatalf("Revoke (again): %v", err)
	}

	// Revoking an unknown session id is also a no-op, not an error.
	if err := store.Revoke(auth.NewSessionID()); err != nil {
		t.Fatalf("Revoke (unknown id): %v", err)
	}
}

func TestDBSessionStore_RevokeAll(t *testing.T) {
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	userID := sessionFixtureUser(t, ctx, pool)
	store := NewDBSessionStore(pool)

	tok1 := "revokeall-1-" + uuid.New().String()
	tok2 := "revokeall-2-" + uuid.New().String()
	for _, tok := range []string{tok1, tok2} {
		sess := auth.Session{
			ID:               auth.NewSessionID(),
			UserID:           userID.String(),
			RefreshTokenHash: auth.HashRefreshToken(tok),
			IssuedAt:         time.Now(),
			ExpiresAt:        time.Now().Add(1 * time.Hour),
		}
		if err := store.Create(sess); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	if err := store.RevokeAll(userID.String()); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	if _, err := store.Validate(tok1); err != auth.ErrSessionNotFound {
		t.Fatalf("Validate(tok1) after RevokeAll: err = %v, want auth.ErrSessionNotFound", err)
	}
	if _, err := store.Validate(tok2); err != auth.ErrSessionNotFound {
		t.Fatalf("Validate(tok2) after RevokeAll: err = %v, want auth.ErrSessionNotFound", err)
	}
}

func TestDBSessionStore_Validate_Expired(t *testing.T) {
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	userID := sessionFixtureUser(t, ctx, pool)
	store := NewDBSessionStore(pool)

	tok := "expired-" + uuid.New().String()
	sess := auth.Session{
		ID:               auth.NewSessionID(),
		UserID:           userID.String(),
		RefreshTokenHash: auth.HashRefreshToken(tok),
		IssuedAt:         time.Now().Add(-2 * time.Hour),
		ExpiresAt:        time.Now().Add(-1 * time.Hour), // already expired
	}
	if err := store.Create(sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := store.Validate(tok); err != auth.ErrSessionNotFound {
		t.Fatalf("Validate (expired): err = %v, want auth.ErrSessionNotFound", err)
	}

	// GetByRefreshToken still returns the (expired) row directly —
	// only Validate applies the Active() check.
	got, err := store.GetByRefreshToken(tok)
	if err != nil {
		t.Fatalf("GetByRefreshToken (expired): %v", err)
	}
	if got.Active(time.Now()) {
		t.Fatal("GetByRefreshToken (expired): session should not report Active")
	}
}
