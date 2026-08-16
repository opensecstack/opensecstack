package handlers_test

// Shared live-Postgres test helper for the 13-file slice of handlers owned by
// this test batch (templates, channel_message_reactions, opengraph, bookmarks,
// upload, mod_notes, api_keys, invites, verify_email, user_directory,
// password_change, archive, scheduled). Named distinctively (the "13" suffix)
// to avoid colliding with helpers other agents may add elsewhere in this
// package while working on other files in parallel.
//
// Connects to the live Postgres instance used for integration testing. If it
// is not reachable, tests that need it call t.Skip via requireLiveDB13.

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/db"
)

const liveTestDBURL13 = "postgres://apiguard@localhost:5434/community_test?sslmode=disable"

// live13Pool lazily connects (once per test binary run) to the live test
// database and applies migrations. Returns nil if the DB is not reachable.
var live13PoolCache *pgxpool.Pool

func live13Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if live13PoolCache != nil {
		return live13PoolCache
	}
	pool, err := db.Connect(liveTestDBURL13, 5)
	if err != nil {
		t.Skipf("live test DB not reachable, skipping integration test: %v", err)
		return nil
	}
	if err := db.Migrate(pool); err != nil {
		t.Skipf("could not migrate live test DB, skipping integration test: %v", err)
		return nil
	}
	live13PoolCache = pool
	return pool
}

// newLiveDeps13 returns Deps wired to the live test database, along with a
// pepper-configured Config suitable for password_change tests.
func newLiveDeps13(t *testing.T) handlers.Deps {
	t.Helper()
	pool := live13Pool(t)
	return handlers.Deps{
		Pool: pool,
		Cfg:  &config.Config{Pepper: "test-pepper"},
	}
}

// mkUser13 inserts a throwaway user with a random unique username and returns
// (id, username).
func mkUser13(t *testing.T, pool *pgxpool.Pool, role string) (id, username string) {
	t.Helper()
	username = "u13_" + uuid.New().String()[:8]
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (id, username, display_name, bio, role, created_at, updated_at, email_verified, totp_enabled, banned, website, github_username, twitter_username, location, certifications, specialization)
		 VALUES (gen_random_uuid(), $1, $1, '', $2, now(), now(), false, false, false, '', '', '', '', '', '')
		 RETURNING id`,
		username, role,
	).Scan(&id)
	if err != nil {
		t.Fatalf("mkUser13: %v", err)
	}
	return id, username
}

// mkPost13 inserts a throwaway post authored by authorID and returns its id.
func mkPost13(t *testing.T, pool *pgxpool.Pool, authorID, state string) string {
	t.Helper()
	var id string
	slug := "p13-" + uuid.New().String()[:8]
	err := pool.QueryRow(context.Background(),
		`INSERT INTO posts (id, author_id, title, slug, body, state, created_at, updated_at, views, sensitive, locked, pinned)
		 VALUES (gen_random_uuid(), $1, $2, $2, 'body', $3, now(), now(), 0, false, false, false)
		 RETURNING id`,
		authorID, slug, state,
	).Scan(&id)
	if err != nil {
		t.Fatalf("mkPost13: %v", err)
	}
	return id
}

// cleanup13 deletes rows created for a test by primary key ids, best-effort.
func cleanup13(pool *pgxpool.Pool, table, column string, ids ...string) {
	if pool == nil {
		return
	}
	for _, id := range ids {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DELETE FROM %s WHERE %s = $1`, table, column), id) //nolint:gosec // test-only, fixed table/column set
	}
}
