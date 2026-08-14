//go:build integration

package consent

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used elsewhere in sinauth.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SINAUTH_TEST_DB_URL")
	if url == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping consent store integration test")
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

// createTestClient inserts a minimal oauth_clients row (oauth_consents.
// client_id FKs to oauth_clients.client_id) and returns its client_id.
func createTestClient(t *testing.T, pool *pgxpool.Pool, clientID string) string {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO oauth_clients (client_id, name) VALUES ($1, $2)`,
		clientID, "Test Client "+clientID,
	)
	if err != nil {
		t.Fatalf("createTestClient: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE client_id=$1`, clientID)
	})
	return clientID
}

func TestStore_GetGrantedScopes_NoConsent(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("nouser%d", time.Now().UnixNano()))
	clientID := createTestClient(t, pool, fmt.Sprintf("no-consent-client-%d", time.Now().UnixNano()))

	scopes, err := s.GetGrantedScopes(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetGrantedScopes = %v, want nil error even with no row", err)
	}
	if len(scopes) != 0 {
		t.Fatalf("GetGrantedScopes = %v, want empty for a user/client with no consent row", scopes)
	}
}

func TestStore_UpsertGetDelete_RoundTrip(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("cuser%d", time.Now().UnixNano()))
	clientID := createTestClient(t, pool, fmt.Sprintf("consent-client-%d", time.Now().UnixNano()))

	if err := s.Upsert(ctx, userID, clientID, []string{"openid", "profile"}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	scopes, err := s.GetGrantedScopes(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetGrantedScopes: %v", err)
	}
	if !sameSet(scopes, []string{"openid", "profile"}) {
		t.Fatalf("GetGrantedScopes = %v, want [openid profile]", scopes)
	}

	if err := s.Delete(ctx, userID, clientID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	scopes, err = s.GetGrantedScopes(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetGrantedScopes after Delete: %v", err)
	}
	if len(scopes) != 0 {
		t.Fatalf("GetGrantedScopes after Delete = %v, want empty", scopes)
	}
}

// TestStore_Upsert_ReplacesRatherThanUnions documents observed behavior:
// Upsert's ON CONFLICT clause does `SET scopes = EXCLUDED.scopes`, which
// REPLACES the stored scope set wholesale rather than unioning it with
// whatever was previously granted. A second Grant/Upsert call with a
// narrower or different scope list therefore silently drops previously
// granted scopes rather than accumulating them. This is not a privilege
// escalation (it fails closed: HasConsent for the dropped scope will
// correctly report false again, forcing a fresh consent prompt) but it is
// a real behavioral gotcha for any call site that assumes consent
// accumulates across multiple authorization requests with different scope
// subsets — pinned down here so a future change to "union" semantics is
// deliberate, not an accidental regression either direction.
func TestStore_Upsert_ReplacesRatherThanUnions(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("replaceuser%d", time.Now().UnixNano()))
	clientID := createTestClient(t, pool, fmt.Sprintf("replace-client-%d", time.Now().UnixNano()))

	if err := s.Upsert(ctx, userID, clientID, []string{"openid", "profile", "email"}); err != nil {
		t.Fatalf("Upsert (broad): %v", err)
	}
	if err := s.Upsert(ctx, userID, clientID, []string{"openid"}); err != nil {
		t.Fatalf("Upsert (narrow): %v", err)
	}

	scopes, err := s.GetGrantedScopes(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetGrantedScopes: %v", err)
	}
	if !sameSet(scopes, []string{"openid"}) {
		t.Fatalf("GetGrantedScopes after narrower Upsert = %v, want exactly [openid] (replace semantics, not union)", scopes)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, x := range b {
		if !set[x] {
			return false
		}
	}
	return true
}
