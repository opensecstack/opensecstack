//go:build integration

// Integration smoke test for New/Ping/Close against a live Postgres.
// Requires CYBERPATH_TEST_DB_URL; skipped otherwise.
package db

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestNew_Success(t *testing.T) {
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	d, err := New(ctx, url, 4)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d == nil || d.Pool == nil {
		t.Fatal("New: expected a populated DB with a non-nil Pool")
	}
	defer d.Close()

	if err := d.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	d.Close()
	// Close must be idempotent.
	d.Close()
}
