// Integration test against a real Postgres instance. Skipped unless
// OPENSCRUB_TEST_DB_URL is set (see rule_store_integration_test.go for
// the full convention).

package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/opensecstack/openscrub/internal/db"
)

func TestIOCIngestLogStoreInsertAndDedup(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewIOCIngestLogStore(pool)
	ctx := context.Background()

	got, err := store.Insert(ctx, "threatflow", "deadbeef", 42)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if got.Source != "threatflow" || got.BundleSHA256 != "deadbeef" || got.Count != 42 {
		t.Fatalf("unexpected row: %+v", got)
	}
	if got.IngestedAt.IsZero() {
		t.Fatal("expected IngestedAt to be populated")
	}

	// Re-inserting the same (source, bundle_sha256) must hit the
	// UNIQUE constraint and translate to the sentinel error the
	// worker uses to skip already-applied bundles.
	_, err = store.Insert(ctx, "threatflow", "deadbeef", 99)
	if !errors.Is(err, db.ErrIOCBundleAlreadyIngested) {
		t.Fatalf("expected ErrIOCBundleAlreadyIngested, got %v", err)
	}

	// Same hash, different source must NOT collide — the UNIQUE
	// constraint is on the (source, bundle_sha256) pair.
	got2, err := store.Insert(ctx, "opencsirt", "deadbeef", 7)
	if err != nil {
		t.Fatalf("insert distinct source: %v", err)
	}
	if got2.Source != "opencsirt" {
		t.Fatalf("unexpected row: %+v", got2)
	}
}

func TestIOCIngestLogStoreLastForSource(t *testing.T) {
	pool := openTestDB(t)
	store := db.NewIOCIngestLogStore(pool)
	ctx := context.Background()

	// No rows for this source yet: LastForSource must return a zero
	// value and no error (not sql.ErrNoRows leaking to the caller).
	got, err := store.LastForSource(ctx, "nobody-pulled-this-yet")
	if err != nil {
		t.Fatalf("expected no error for missing source, got %v", err)
	}
	if got.ID.String() != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("expected zero-value log, got %+v", got)
	}

	if _, err := store.Insert(ctx, "threatflow", "hash-1", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Insert(ctx, "threatflow", "hash-2", 2); err != nil {
		t.Fatal(err)
	}

	last, err := store.LastForSource(ctx, "threatflow")
	if err != nil {
		t.Fatal(err)
	}
	if last.BundleSHA256 != "hash-2" || last.Count != 2 {
		t.Fatalf("expected most recent ingest (hash-2), got %+v", last)
	}
}
