package db_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/db"
)

// randomSuffix returns a short random hex string for building collision-free
// usernames in DB-backed tests that share the test DB with other suites.
func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// defaultTestDBURL mirrors internal/api/handlers/oauth_testutil_internal_test.go's
// convention: COMMUNITY_TEST_DB_URL if set, otherwise the local docker-compose
// test Postgres instance.
const defaultTestDBURL = "postgres://apiguard@localhost:5434/community_test?sslmode=disable"

// testPool returns a migrated pool against the real test Postgres instance,
// skipping the test entirely when no DB is reachable so this suite degrades
// gracefully in environments without Postgres (e.g. some CI sandboxes).
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("COMMUNITY_TEST_DB_URL")
	if url == "" {
		url = defaultTestDBURL
	}
	pool, err := db.Connect(url, 5)
	if err != nil {
		t.Skipf("real test DB unavailable, skipping DB-backed test: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return pool
}

// TestMigrate_Success proves Migrate's happy path (every DDL statement
// applied, nil error returned) against a real database — the existing
// TestMigrate_DBError_ReturnsWrappedError only exercises the error branch.
func TestMigrate_Success(t *testing.T) {
	pool := testPool(t)

	// Migrations use `IF NOT EXISTS` guards, so calling Migrate a second
	// time against an already-migrated database must still succeed
	// (idempotency), exercising the loop-completes-without-error path.
	if err := db.Migrate(pool); err != nil {
		t.Fatalf("second Migrate call: %v", err)
	}
}

// TestLogAudit_InsertsRow proves LogAudit writes a row with the given
// fields into audit_log using a real connection.
func TestLogAudit_InsertsRow(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// actor_id has an FK to users(id), so a row must exist for the insert
	// to succeed (LogAudit swallows any Exec error, so an FK violation
	// would otherwise fail silently and this test would see no row).
	var actorID string
	username := "audit-test-user-" + randomSuffix()
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username) VALUES ($1) RETURNING id`, username,
	).Scan(&actorID)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, actorID)
	})

	db.LogAudit(ctx, pool, actorID, "user.ban", "user", "target-123", "test note")

	var action, targetType, targetID, note string
	err = pool.QueryRow(ctx,
		`SELECT action, target_type, target_id, note FROM audit_log
		 WHERE action = $1 AND target_type = $2 AND target_id = $3
		 ORDER BY created_at DESC LIMIT 1`,
		"user.ban", "user", "target-123",
	).Scan(&action, &targetType, &targetID, &note)
	if err != nil {
		t.Fatalf("query inserted audit row: %v", err)
	}
	if action != "user.ban" || targetType != "user" || targetID != "target-123" || note != "test note" {
		t.Errorf("audit row = (%q,%q,%q,%q), want (user.ban,user,target-123,test note)", action, targetType, targetID, note)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_log WHERE target_id = $1`, "target-123")
	})
}

// TestLogAudit_NilActorID proves LogAudit tolerates an empty actor_id
// (the column is nullable — a "system" action with no human actor).
func TestLogAudit_NilActorID(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// LogAudit swallows the Exec error (fire-and-forget), so passing an
	// empty string for a UUID column must not panic even if it fails to
	// parse as a UUID; we only assert this doesn't crash the test.
	db.LogAudit(ctx, pool, "", "system.startup", "system", "", "")
}
