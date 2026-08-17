//go:build integration

package token

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used elsewhere in sinauth (see
// internal/organization/store_test.go, internal/rbac/store_test.go).
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SINAUTH_TEST_DB_URL")
	if url == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping token store integration test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func createTestUser(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id`,
		username, username+"@example.com",
	).Scan(&id)
	if err != nil {
		t.Fatalf("createTestUser: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, id) })
	return id
}

func createTestClient(t *testing.T, pool *pgxpool.Pool, clientID string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO oauth_clients (client_id, name, redirect_uris) VALUES ($1, $2, '{}')`,
		clientID, "Test Client "+clientID,
	)
	if err != nil {
		t.Fatalf("createTestClient: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE client_id=$1`, clientID)
	})
}

func TestStore_SaveAndConsumeRefreshToken(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	userID := createTestUser(t, pool, "rt-save-consume-user")
	createTestClient(t, pool, "rt-save-consume-client")

	raw := "raw-refresh-token-happy-path"
	if err := s.SaveRefreshToken(context.Background(), raw, "rt-save-consume-client", userID, []string{"openid", "profile"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	clientID, gotUserID, scopes, err := s.ConsumeRefreshToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("ConsumeRefreshToken: %v", err)
	}
	if clientID != "rt-save-consume-client" {
		t.Errorf("clientID = %q, want rt-save-consume-client", clientID)
	}
	if gotUserID != userID {
		t.Errorf("userID = %q, want %q", gotUserID, userID)
	}
	if len(scopes) != 2 || scopes[0] != "openid" || scopes[1] != "profile" {
		t.Errorf("scopes = %v, want [openid profile]", scopes)
	}
}

// TestStore_ConsumeRefreshToken_IsOneTimeUse is a replay-protection test:
// refresh token rotation depends on each raw token being consumable exactly
// once. ConsumeRefreshToken deletes the row it returns; if a stolen/leaked
// refresh token could be redeemed more than once, an attacker who captured
// one refresh request could keep minting new tokens indefinitely alongside
// the legitimate client, without any way to detect the theft.
func TestStore_ConsumeRefreshToken_IsOneTimeUse(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	userID := createTestUser(t, pool, "rt-onetime-user")
	createTestClient(t, pool, "rt-onetime-client")

	raw := "raw-refresh-token-onetime"
	if err := s.SaveRefreshToken(context.Background(), raw, "rt-onetime-client", userID, []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	if _, _, _, err := s.ConsumeRefreshToken(context.Background(), raw); err != nil {
		t.Fatalf("ConsumeRefreshToken (1st): %v", err)
	}
	if _, _, _, err := s.ConsumeRefreshToken(context.Background(), raw); err == nil {
		t.Fatal("ConsumeRefreshToken (2nd / replay): expected error — refresh token must be single-use")
	}
}

// TestStore_ConsumeRefreshToken_ExpiredRejected proves a refresh token past
// its expires_at cannot be consumed even though it was never revoked or used.
func TestStore_ConsumeRefreshToken_ExpiredRejected(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	userID := createTestUser(t, pool, "rt-expired-user")
	createTestClient(t, pool, "rt-expired-client")

	raw := "raw-refresh-token-expired"
	if err := s.SaveRefreshToken(context.Background(), raw, "rt-expired-client", userID, []string{"openid"}, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	if _, _, _, err := s.ConsumeRefreshToken(context.Background(), raw); err == nil {
		t.Fatal("ConsumeRefreshToken: expected error for expired token, got nil")
	}
}

// TestStore_RevokeRefreshToken_PreventsConsumption proves that revoking a
// refresh token (e.g. on logout, or when theft is detected) makes it
// immediately unusable, even though it hasn't expired.
func TestStore_RevokeRefreshToken_PreventsConsumption(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	userID := createTestUser(t, pool, "rt-revoke-user")
	createTestClient(t, pool, "rt-revoke-client")

	raw := "raw-refresh-token-revoke"
	if err := s.SaveRefreshToken(context.Background(), raw, "rt-revoke-client", userID, []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	if err := s.RevokeRefreshToken(context.Background(), raw); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}

	if _, _, _, err := s.ConsumeRefreshToken(context.Background(), raw); err == nil {
		t.Fatal("ConsumeRefreshToken: expected error for revoked token, got nil")
	}
}

// TestStore_SaveRefreshToken_NeverPersistsPlaintext proves the raw token
// string is not stored verbatim anywhere retrievable — only its SHA-256
// hash — so a database read/leak alone can't be used to forge a valid
// refresh token.
func TestStore_SaveRefreshToken_NeverPersistsPlaintext(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	userID := createTestUser(t, pool, "rt-hash-only-user")
	createTestClient(t, pool, "rt-hash-only-client")

	raw := "super-secret-raw-refresh-token-value"
	if err := s.SaveRefreshToken(context.Background(), raw, "rt-hash-only-client", userID, []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM refresh_tokens WHERE token_hash = $1`, raw,
	).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 0 {
		t.Error("found a refresh_tokens row keyed by the raw plaintext token — token_hash must store a hash, not the raw value")
	}
}

func TestStore_ConsumeRefreshToken_UnknownTokenFails(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)

	if _, _, _, err := s.ConsumeRefreshToken(context.Background(), "never-issued-token"); err == nil {
		t.Fatal("ConsumeRefreshToken: expected error for unknown token, got nil")
	}
}
