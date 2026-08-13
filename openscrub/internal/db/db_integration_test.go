// Integration test against a real Postgres instance. Skipped unless
// OPENSCRUB_TEST_DB_URL is set (see rule_store_integration_test.go for
// the full convention).

package db_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/opensecstack/openscrub/internal/db"
)

// TestDBNewPingClose covers the constructor's happy path: a valid DSN
// opens a pool, pings it successfully, and Close releases it cleanly
// (no panic, and the pool is unusable afterward).
func TestDBNewPingClose(t *testing.T) {
	url := os.Getenv("OPENSCRUB_TEST_DB_URL")
	if url == "" {
		t.Skip("OPENSCRUB_TEST_DB_URL unset — skipping integration")
	}

	d, err := db.New(context.Background(), url, 4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d == nil || d.Pool == nil {
		t.Fatal("New returned a DB with a nil pool")
	}

	if err := d.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	d.Close()

	// After Close, the pool must refuse further use rather than panic.
	if err := d.Pool.Ping(context.Background()); err == nil {
		t.Fatal("expected ping on a closed pool to fail")
	}
}

// TestDBNewInvalidURL covers the ParseConfig error branch: a
// malformed DSN must return an error, not panic, and must not require
// a live Postgres to observe.
func TestDBNewInvalidURL(t *testing.T) {
	_, err := db.New(context.Background(), "not-a-valid-url://\x7f", 1)
	if err == nil {
		t.Fatal("expected error for invalid DB URL")
	}
}

// TestDBNewUnreachable covers the initial-ping error branch: a
// syntactically valid DSN pointing at a port nothing listens on must
// fail fast rather than hang or return a live DB.
func TestDBNewUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := db.New(ctx, "postgres://nouser@127.0.0.1:1/nosuchdb?sslmode=disable&connect_timeout=1", 1)
	if err == nil {
		t.Fatal("expected error connecting to an unreachable DB")
	}
}
