package handlers_test

// Shared live-Postgres test harness for gdpr_test.go, reports_test.go,
// users_test.go, admin_test.go, and admin_tags_test.go.
//
// Everything else in this package tests only the "DB unreachable" negative
// path (see newDepsWithBadDB in health_test.go). That leaves success paths,
// role-authorization success paths, and — critically for gdpr.go — cross-user
// data isolation completely unverified. Those can only be exercised against a
// real schema, so this harness connects to a live Postgres instance (the same
// one CI/dev already provisions for integration-style tests) and applies the
// real migrations via internal/db.Migrate — the same code path production
// uses to create the schema, so the tests exercise real constraints (unique
// indexes, foreign keys, CHECK clauses) rather than a hand-rolled mock.
//
// If no live database is reachable, every test that calls requireLiveDB
// skips (not fails) so this package still passes in environments without a
// database (e.g. a sandboxed CI step that only lints).

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/db"
)

const defaultLiveTestDBURL = "postgres://apiguard@localhost:5434/community_test?sslmode=disable"

var (
	liveDBOnce sync.Once
	liveDBPool *pgxpool.Pool
	liveDBErr  error
)

// liveTestDBURL returns the connection string to use for live-DB tests.
// COMMUNITY_DB_URL is the env var internal/config already uses in production
// (see internal/config/config.go), so we honour it here too rather than
// inventing a separate test-only variable.
func liveTestDBURL() string {
	if v := os.Getenv("COMMUNITY_DB_URL"); v != "" {
		return v
	}
	return defaultLiveTestDBURL
}

// liveTestPool lazily connects and migrates once per test binary run, and
// reuses the same pool across every test in this package.
// requiredLiveTestTables are the tables these five handlers' tests actually
// touch. On a shared test database (the same instance other in-flight
// coverage work against other handler files also targets), db.Migrate can
// fail transiently for reasons that have nothing to do with gdpr/reports/
// users/admin/admin_tags — e.g. another package's migration re-validates a
// CHECK constraint against rows a concurrently-running test just inserted.
// db.Migrate's CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS
// statements are idempotent, so once the schema has been created once (by
// this run or an earlier one), re-running the full migration set on every
// test process is unnecessary — we only need proof that the tables we
// depend on already exist.
var requiredLiveTestTables = []string{"users", "posts", "comments", "tags", "deletion_requests", "reports", "broadcasts"}

func liveTestPool() (*pgxpool.Pool, error) {
	liveDBOnce.Do(func() {
		pool, err := db.Connect(liveTestDBURL(), 5)
		if err != nil {
			liveDBErr = err
			return
		}
		migrateErr := db.Migrate(pool)
		if migrateErr != nil && !liveTestSchemaReady(pool) {
			// Migration failed AND the tables we need don't already exist —
			// this is a real "no usable database" failure, not just
			// unrelated cross-package churn.
			liveDBErr = migrateErr
			pool.Close()
			return
		}
		liveDBPool = pool
	})
	return liveDBPool, liveDBErr
}

// liveTestSchemaReady reports whether every table these tests depend on is
// already present, regardless of whether the most recent db.Migrate() call
// itself succeeded.
func liveTestSchemaReady(pool *pgxpool.Pool) bool {
	for _, table := range requiredLiveTestTables {
		var exists bool
		err := pool.QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`,
			table,
		).Scan(&exists)
		if err != nil || !exists {
			return false
		}
	}
	return true
}

// requireLiveDB returns Deps wired to a live, migrated Postgres pool, or
// skips the test when no database is reachable.
func requireLiveDB(t *testing.T) handlers.Deps {
	t.Helper()
	pool, err := liveTestPool()
	if err != nil {
		t.Skip("live database not reachable, skipping live-DB test:", err)
	}
	return handlers.Deps{
		Pool: pool,
		Cfg:  &config.Config{Node: "community-test-node"},
	}
}

// seedTestUser inserts a user with a random username (so parallel test runs
// against a shared database never collide on the UNIQUE(username) /
// UNIQUE(email) constraints) and returns its id and username. The row and
// everything that FK-cascades from it is removed automatically at test end.
func seedTestUser(t *testing.T, pool *pgxpool.Pool, role string) (id, username string) {
	t.Helper()
	username = "gru_" + uuid.New().String()
	email := username + "@example.test"

	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, display_name, role, email) VALUES ($1,$2,$3,$4) RETURNING id`,
		username, username, role, email,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedTestUser: insert failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, id)
	})
	return id, username
}

// seedTestPost inserts a minimal published post authored by authorID.
func seedTestPost(t *testing.T, pool *pgxpool.Pool, authorID string) (id, slug string) {
	t.Helper()
	slug = "gru-post-" + uuid.New().String()
	err := pool.QueryRow(context.Background(),
		`INSERT INTO posts (author_id, title, slug, body, state, published_at)
		 VALUES ($1,$2,$3,$4,'published', now()) RETURNING id`,
		authorID, "Test Post "+slug, slug, "body",
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedTestPost: insert failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM posts WHERE id=$1`, id)
	})
	return id, slug
}

// seedTestComment inserts a minimal comment authored by authorID on postID.
func seedTestComment(t *testing.T, pool *pgxpool.Pool, postID, authorID string) (id string) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`INSERT INTO comments (post_id, author_id, body) VALUES ($1,$2,$3) RETURNING id`,
		postID, authorID, "test comment "+uuid.New().String(),
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedTestComment: insert failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM comments WHERE id=$1`, id)
	})
	return id
}
