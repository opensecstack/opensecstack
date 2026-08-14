//go:build integration

package session

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used elsewhere in sinauth (e.g.
// internal/rbac/store_test.go, internal/organization/store_test.go).
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SINAUTH_TEST_DB_URL")
	if url == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping session store integration test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// createTestUser inserts a minimal user row and returns its id.
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

func TestStore_CreateGet_RoundTrip(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("sessuser%d", time.Now().UnixNano()))

	sess, err := s.Create(ctx, userID, "sessuser", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, sess.ID) })

	if sess.ID == "" {
		t.Fatal("Create returned empty session ID")
	}
	if sess.UserID != userID {
		t.Errorf("session.UserID = %q, want %q", sess.UserID, userID)
	}
	if sess.Username != "sessuser" {
		t.Errorf("session.Username = %q, want %q", sess.Username, "sessuser")
	}

	got, err := s.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != sess.ID || got.UserID != userID || got.Username != "sessuser" {
		t.Errorf("Get = %+v, want id=%s user=%s username=sessuser", got, sess.ID, userID)
	}
	if got.CreatedAt.IsZero() {
		t.Error("Get: CreatedAt is zero, want a populated timestamp")
	}
	if !got.ExpiresAt.After(got.CreatedAt) {
		t.Errorf("Get: ExpiresAt (%v) should be after CreatedAt (%v)", got.ExpiresAt, got.CreatedAt)
	}
}

// TestStore_Create_UniqueRandomIDs proves each Create call mints a distinct
// unguessable session ID (32 random bytes hex-encoded) — a collision or a
// predictable ID generator here would allow session fixation/hijacking.
func TestStore_Create_UniqueRandomIDs(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("iduser%d", time.Now().UnixNano()))

	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		sess, err := s.Create(ctx, userID, "iduser", time.Hour)
		if err != nil {
			t.Fatalf("Create[%d]: %v", i, err)
		}
		t.Cleanup(func(id string) func() { return func() { _ = s.Delete(ctx, id) } }(sess.ID))
		if len(sess.ID) != 64 { // 32 bytes hex-encoded = 64 chars
			t.Errorf("session ID length = %d, want 64 (32 random bytes hex-encoded), id=%q", len(sess.ID), sess.ID)
		}
		if seen[sess.ID] {
			t.Fatalf("Create produced a duplicate session ID: %s", sess.ID)
		}
		seen[sess.ID] = true
	}
}

// TestStore_Get_ExpiredSessionNotReturned is the core expiry-enforcement
// test: a session whose expires_at is in the past must not be returned by
// Get, even though the row still physically exists — Get's WHERE clause
// (`expires_at > now()`) is the only thing standing between an expired
// session and continued access, so this is a security-critical assertion.
func TestStore_Get_ExpiredSessionNotReturned(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("expuser%d", time.Now().UnixNano()))

	// Create with a positive TTL, then rewrite expires_at into the past
	// directly (bypassing Store, since Create's ttl parameter should never
	// accept a negative duration in real call sites) to simulate a session
	// that has since expired.
	sess, err := s.Create(ctx, userID, "expuser", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, sess.ID) })

	if _, err := pool.Exec(ctx, `UPDATE sso_sessions SET expires_at = now() - interval '1 minute' WHERE id=$1`, sess.ID); err != nil {
		t.Fatalf("force-expire session: %v", err)
	}

	if _, err := s.Get(ctx, sess.ID); err == nil {
		t.Fatal("Get returned an expired session, want an error (not found)")
	}
}

// TestStore_Get_UnknownID proves Get errors (rather than returning a
// zero-value session) for an ID that was never created.
func TestStore_Get_UnknownID(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	if _, err := s.Get(ctx, "does-not-exist-0000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("Get for unknown session ID = nil error, want an error")
	}
}

// TestStore_Delete_RevokesSession proves Delete (session revocation, e.g.
// logout) makes an otherwise-valid, non-expired session immediately
// unreadable via Get — the invalidation path an admin/user relies on to
// kill a compromised session.
func TestStore_Delete_RevokesSession(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("revuser%d", time.Now().UnixNano()))
	sess, err := s.Create(ctx, userID, "revuser", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := s.Get(ctx, sess.ID); err != nil {
		t.Fatalf("Get before Delete: %v", err)
	}

	if err := s.Delete(ctx, sess.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.Get(ctx, sess.ID); err == nil {
		t.Fatal("Get after Delete = nil error, want an error (session revoked)")
	}
}

// TestStore_Delete_UnknownID_IsNotAnError proves deleting a non-existent
// session ID is idempotent/harmless (DELETE with no matching rows is not
// an error in Postgres), matching logout-is-idempotent expectations.
func TestStore_Delete_UnknownID_IsNotAnError(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	if err := s.Delete(ctx, "totally-unknown-session-id"); err != nil {
		t.Fatalf("Delete unknown ID = %v, want nil", err)
	}
}

// TestStore_ListAll_ExcludesExpiredAndOrdersNewestFirst covers ListAll:
// it must return only non-expired sessions (concurrent-session visibility
// for admins must not include stale/expired entries) and order newest
// first.
func TestStore_ListAll_ExcludesExpiredAndOrdersNewestFirst(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("listuser%d", time.Now().UnixNano()))

	older, err := s.Create(ctx, userID, "listuser", time.Hour)
	if err != nil {
		t.Fatalf("Create older: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, older.ID) })
	// Ensure a distinguishable created_at ordering (timestamp resolution).
	if _, err := pool.Exec(ctx, `UPDATE sso_sessions SET created_at = now() - interval '1 hour' WHERE id=$1`, older.ID); err != nil {
		t.Fatalf("backdate older session: %v", err)
	}

	newer, err := s.Create(ctx, userID, "listuser", time.Hour)
	if err != nil {
		t.Fatalf("Create newer: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, newer.ID) })

	expired, err := s.Create(ctx, userID, "listuser", time.Hour)
	if err != nil {
		t.Fatalf("Create expired: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, expired.ID) })
	if _, err := pool.Exec(ctx, `UPDATE sso_sessions SET expires_at = now() - interval '1 minute' WHERE id=$1`, expired.ID); err != nil {
		t.Fatalf("force-expire: %v", err)
	}

	all, err := s.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}

	var idxOlder, idxNewer = -1, -1
	for i, sess := range all {
		if sess.ID == expired.ID {
			t.Fatalf("ListAll included an expired session: %s", sess.ID)
		}
		if sess.ID == older.ID {
			idxOlder = i
		}
		if sess.ID == newer.ID {
			idxNewer = i
		}
	}
	if idxOlder == -1 || idxNewer == -1 {
		t.Fatalf("ListAll missing expected sessions: older found=%v newer found=%v", idxOlder != -1, idxNewer != -1)
	}
	if idxNewer >= idxOlder {
		t.Errorf("ListAll order: newer session (idx %d) should come before older session (idx %d) — want newest first", idxNewer, idxOlder)
	}
}

// TestStore_ListByUsername_ScopedToUser proves ListByUsername only returns
// sessions for the requested username, not other users' sessions — a mixup
// here would leak one user's active-session list to another.
func TestStore_ListByUsername_ScopedToUser(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	uniq := time.Now().UnixNano()
	userA := createTestUser(t, pool, fmt.Sprintf("usera%d", uniq))
	userB := createTestUser(t, pool, fmt.Sprintf("userb%d", uniq))
	unameA := fmt.Sprintf("usera%d", uniq)
	unameB := fmt.Sprintf("userb%d", uniq)

	sessA, err := s.Create(ctx, userA, unameA, time.Hour)
	if err != nil {
		t.Fatalf("Create A: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, sessA.ID) })

	sessB, err := s.Create(ctx, userB, unameB, time.Hour)
	if err != nil {
		t.Fatalf("Create B: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, sessB.ID) })

	listA, err := s.ListByUsername(ctx, unameA)
	if err != nil {
		t.Fatalf("ListByUsername A: %v", err)
	}
	for _, sess := range listA {
		if sess.ID == sessB.ID {
			t.Fatalf("ListByUsername(%q) leaked user B's session %s", unameA, sessB.ID)
		}
	}
	var foundA bool
	for _, sess := range listA {
		if sess.ID == sessA.ID {
			foundA = true
		}
	}
	if !foundA {
		t.Fatalf("ListByUsername(%q) missing that user's own session %s", unameA, sessA.ID)
	}
}

// TestStore_Create_ZeroOrNegativeTTL documents current behavior for
// pathological TTLs: a zero/negative TTL yields an already-expired
// session (ExpiresAt <= now), which is safe (fails closed — Get will
// reject it) rather than, say, treating zero as "no expiry".
func TestStore_Create_ZeroOrNegativeTTL(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	userID := createTestUser(t, pool, fmt.Sprintf("ttluser%d", time.Now().UnixNano()))

	sess, err := s.Create(ctx, userID, "ttluser", -time.Minute)
	if err != nil {
		t.Fatalf("Create with negative TTL: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete(ctx, sess.ID) })

	if !sess.ExpiresAt.Before(time.Now()) {
		t.Errorf("Create with negative TTL produced ExpiresAt=%v, want it in the past", sess.ExpiresAt)
	}

	// And Get must reject it immediately, proving the "fails closed" claim.
	if _, err := s.Get(ctx, sess.ID); err == nil {
		t.Fatal("Get on a session created with a negative TTL = nil error, want an error")
	}
}
