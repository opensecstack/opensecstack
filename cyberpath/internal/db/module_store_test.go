//go:build integration

// Integration tests for ModuleStore against the `modules` table.
// ModuleStore is read-only (Get/ListByTrack); rows are seeded here with
// raw SQL since there is no Create method on the store itself. Requires
// CYBERPATH_TEST_DB_URL; skipped otherwise.
package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestModuleStore_GetAndListByTrack(t *testing.T) {
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
	defer pool.Close()

	trackID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tracks (id, slug, title) VALUES ($1, $2, $3)`,
		trackID, "modtest-"+trackID.String()[:8], "Module Test Track"); err != nil {
		t.Fatalf("seed track: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tracks WHERE id = $1`, trackID)
	})

	mod1ID := uuid.New()
	mod2ID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO modules (id, track_id, slug, title, ord) VALUES
			($1, $3, 'mod-a', 'Module A', 1),
			($2, $3, 'mod-b', 'Module B', 0)`,
		mod1ID, mod2ID, trackID); err != nil {
		t.Fatalf("seed modules: %v", err)
	}

	store := NewModuleStore(pool)

	got, err := store.Get(ctx, mod1ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Slug != "mod-a" || got.Title != "Module A" || got.Order != 1 {
		t.Fatalf("Get: unexpected module %+v", got)
	}
	if got.TrackID != trackID {
		t.Fatalf("Get: track_id = %v, want %v", got.TrackID, trackID)
	}

	list, err := store.ListByTrack(ctx, trackID)
	if err != nil {
		t.Fatalf("ListByTrack: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListByTrack: got %d modules, want 2", len(list))
	}
	// ORDER BY ord, slug: mod-b (ord=0) before mod-a (ord=1).
	if list[0].Slug != "mod-b" || list[1].Slug != "mod-a" {
		t.Fatalf("ListByTrack: wrong order: %q, %q", list[0].Slug, list[1].Slug)
	}
}

func TestModuleStore_Get_NotFound(t *testing.T) {
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
	defer pool.Close()

	store := NewModuleStore(pool)

	_, err = store.Get(ctx, uuid.New())
	if !errors.Is(err, ErrModuleNotFound) {
		t.Fatalf("Get: err = %v, want ErrModuleNotFound", err)
	}
}

func TestModuleStore_ListByTrack_Empty(t *testing.T) {
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
	defer pool.Close()

	store := NewModuleStore(pool)

	list, err := store.ListByTrack(ctx, uuid.New())
	if err != nil {
		t.Fatalf("ListByTrack: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListByTrack: got %d modules for unknown track, want 0", len(list))
	}
}
