//go:build integration

// Integration tests for ContentVersionStore. Requires CYBERPATH_TEST_DB_URL
// pointing at a fully-migrated cyberpath schema; otherwise skipped.
package db

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func cvTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestContentVersionStore_PublishAndSupersede(t *testing.T) {
	pool := cvTestPool(t)
	ctx := context.Background()
	store := NewContentVersionStore(pool)

	entityType := "lab" // varchar(128) entity_id, no FK — safe to use a slug id here
	entityID := "lab-" + uuid.NewString()[:8]

	v1, err := store.Publish(ctx, entityType, entityID, json.RawMessage(`{"n":1}`), "hash1", nil, "initial publish")
	if err != nil {
		t.Fatalf("Publish v1: %v", err)
	}
	if v1.Version != 1 {
		t.Fatalf("Publish v1: expected version 1, got %d", v1.Version)
	}
	if v1.SupersededAt != nil {
		t.Fatal("Publish v1: should not be superseded")
	}

	var ids []uuid.UUID
	ids = append(ids, v1.ID)
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = pool.Exec(context.Background(), `DELETE FROM content_versions WHERE id = $1`, id)
		}
	})

	v2, err := store.Publish(ctx, entityType, entityID, json.RawMessage(`{"n":2}`), "hash2", nil, "second publish")
	if err != nil {
		t.Fatalf("Publish v2: %v", err)
	}
	ids = append(ids, v2.ID)
	if v2.Version != 2 {
		t.Fatalf("Publish v2: expected version 2, got %d", v2.Version)
	}

	// v1 must now be superseded.
	v1Reloaded, err := store.GetByID(ctx, v1.ID)
	if err != nil {
		t.Fatalf("GetByID v1: %v", err)
	}
	if v1Reloaded.SupersededAt == nil {
		t.Fatal("Publish v2 did not supersede v1")
	}

	latest, err := store.GetLatest(ctx, entityType, entityID)
	if err != nil {
		t.Fatalf("GetLatest: %v", err)
	}
	if latest.ID != v2.ID {
		t.Fatalf("GetLatest: expected v2 (%s), got %s", v2.ID, latest.ID)
	}

	gotV1, err := store.GetVersion(ctx, entityType, entityID, 1)
	if err != nil {
		t.Fatalf("GetVersion(1): %v", err)
	}
	if gotV1.ID != v1.ID {
		t.Fatalf("GetVersion(1): id mismatch got %s want %s", gotV1.ID, v1.ID)
	}

	all, err := store.ListVersions(ctx, entityType, entityID)
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListVersions: expected 2, got %d", len(all))
	}
	if all[0].Version != 2 || all[1].Version != 1 {
		t.Fatalf("ListVersions: expected newest-first order, got %+v", all)
	}
}

func TestContentVersionStore_NotFoundPaths(t *testing.T) {
	pool := cvTestPool(t)
	ctx := context.Background()
	store := NewContentVersionStore(pool)

	if _, err := store.GetByID(ctx, uuid.New()); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetByID(unknown) expected pgx.ErrNoRows, got %v", err)
	}

	entityID := "no-such-lab-" + uuid.NewString()
	if _, err := store.GetLatest(ctx, "lab", entityID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetLatest(unknown) expected pgx.ErrNoRows, got %v", err)
	}

	if _, err := store.GetVersion(ctx, "lab", entityID, 1); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("GetVersion(unknown) expected pgx.ErrNoRows, got %v", err)
	}

	list, err := store.ListVersions(ctx, "lab", entityID)
	if err != nil {
		t.Fatalf("ListVersions(unknown): unexpected error %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListVersions(unknown): expected 0 rows, got %d", len(list))
	}
}

func TestContentVersionStore_DeleteForbiddenByTrigger(t *testing.T) {
	pool := cvTestPool(t)
	ctx := context.Background()
	store := NewContentVersionStore(pool)

	entityID := "trig-" + uuid.NewString()[:8]
	v, err := store.Publish(ctx, "quiz", entityID, json.RawMessage(`{}`), "hashx", nil, "")
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM content_versions WHERE id = $1`, v.ID)
	})

	// content_versions is append-only: DELETE must be rejected by the
	// BEFORE DELETE trigger, proving the audit-evidence immutability
	// guarantee actually holds at the DB level (not just by convention).
	_, err = pool.Exec(ctx, `DELETE FROM content_versions WHERE id = $1`, v.ID)
	if err == nil {
		t.Fatal("expected DELETE on content_versions to be rejected by trigger, got nil error")
	}
}

func TestContentVersionStore_InvalidEntityTypeRejected(t *testing.T) {
	pool := cvTestPool(t)
	ctx := context.Background()
	store := NewContentVersionStore(pool)

	_, err := store.Publish(ctx, "not-a-real-type", "x-"+uuid.NewString()[:8], json.RawMessage(`{}`), "h", nil, "")
	if err == nil {
		t.Fatal("expected CHECK constraint violation for invalid entity_type, got nil error")
	}
}
