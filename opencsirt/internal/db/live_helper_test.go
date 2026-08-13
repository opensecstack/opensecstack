package db

import (
	"context"
	"os"
	"testing"
)

// liveDB returns a pool connected to a real Postgres instance for tests that
// exercise success paths (row round-tripping, constraint violations, filter
// semantics) that an unreachable-pool test can never reach. It reads
// DATABASE_URL — this package has no prior DB-test env var convention, so
// DATABASE_URL is used, matching the sibling platforms in this monorepo
// (apiguard, securelab, vertguard). The schema is expected to already be
// migrated (see migrations/) before the test binary runs.
//
// Tests using liveDB skip cleanly (not fail) when DATABASE_URL is unset, so
// this package still passes in environments without a live Postgres.
func liveDB(t *testing.T) *Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping live database test")
	}
	pool, err := Open(context.Background(), dsn, 4)
	if err != nil {
		t.Fatalf("Open(DATABASE_URL): %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Fatalf("ping live database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
