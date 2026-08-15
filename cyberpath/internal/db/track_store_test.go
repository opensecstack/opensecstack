//go:build integration

// Integration tests for TrackStore. Requires CYBERPATH_TEST_DB_URL pointing
// at a fully-migrated cyberpath schema; otherwise skipped.
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

func trackTestPool(t *testing.T) *pgxpool.Pool {
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

// insertTrack inserts a bare track row and registers cleanup.
func insertTrack(t *testing.T, pool *pgxpool.Pool, slug string, published bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	_, err := pool.Exec(ctx, `
		INSERT INTO tracks (id, slug, title, locale, difficulty, tags, nis2_refs, published)
		VALUES ($1,$2,$3,'en','beginner', ARRAY['t1','t2'], ARRAY['Art.21'], $4)`,
		id, slug, "Track "+slug, published)
	if err != nil {
		t.Fatalf("seed track: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tracks WHERE id = $1`, id)
	})
	return id
}

func TestTrackStore_GetAndGetBySlug(t *testing.T) {
	pool := trackTestPool(t)
	ctx := context.Background()
	slug := "trk-" + uuid.NewString()[:8]
	id := insertTrack(t, pool, slug, true)

	store := NewTrackStore(pool)

	got, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Slug != slug || !got.Published {
		t.Fatalf("Get: unexpected row %+v", got)
	}
	if len(got.Tags) != 2 || len(got.NIS2Refs) != 1 {
		t.Fatalf("Get: arrays not scanned correctly: %+v", got)
	}

	bySlug, err := store.GetBySlug(ctx, slug)
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	if bySlug.ID != id {
		t.Fatalf("GetBySlug: id mismatch got %s want %s", bySlug.ID, id)
	}
}

func TestTrackStore_Get_NotFound(t *testing.T) {
	pool := trackTestPool(t)
	ctx := context.Background()
	store := NewTrackStore(pool)

	_, err := store.Get(ctx, uuid.New())
	if !errors.Is(err, ErrTrackNotFound) {
		t.Fatalf("expected ErrTrackNotFound, got %v", err)
	}

	_, err = store.GetBySlug(ctx, "no-such-slug-"+uuid.NewString())
	if !errors.Is(err, ErrTrackNotFound) {
		t.Fatalf("GetBySlug expected ErrTrackNotFound, got %v", err)
	}
}

func TestTrackStore_List(t *testing.T) {
	pool := trackTestPool(t)
	ctx := context.Background()
	store := NewTrackStore(pool)

	prefix := "list-" + uuid.NewString()[:8]
	pubID := insertTrack(t, pool, prefix+"-pub", true)
	unpubID := insertTrack(t, pool, prefix+"-unpub", false)

	pub := true
	list, err := store.List(ctx, TrackFilter{Published: &pub})
	if err != nil {
		t.Fatalf("List published: %v", err)
	}
	foundPub, foundUnpub := false, false
	for _, tr := range list {
		if tr.ID == pubID {
			foundPub = true
		}
		if tr.ID == unpubID {
			foundUnpub = true
		}
	}
	if !foundPub {
		t.Fatal("List(published=true) missing the published track")
	}
	if foundUnpub {
		t.Fatal("List(published=true) leaked the unpublished track")
	}

	all, err := store.List(ctx, TrackFilter{Locale: "en", Limit: 500})
	if err != nil {
		t.Fatalf("List locale: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("List(locale=en) returned no rows")
	}

	pubOnly, err := store.ListPublished(ctx)
	if err != nil {
		t.Fatalf("ListPublished: %v", err)
	}
	found := false
	for _, tr := range pubOnly {
		if tr.ID == pubID {
			found = true
		}
	}
	if !found {
		t.Fatal("ListPublished missing our published track")
	}
}

func TestTrackStore_GetByModule(t *testing.T) {
	pool := trackTestPool(t)
	ctx := context.Background()
	store := NewTrackStore(pool)

	slug := "mod-trk-" + uuid.NewString()[:8]
	trackID := insertTrack(t, pool, slug, true)

	moduleID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO modules (id, track_id, slug, title, ord)
		VALUES ($1,$2,'m1','Module 1', 0)`, moduleID, trackID); err != nil {
		t.Fatalf("seed module: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM modules WHERE id = $1`, moduleID)
	})

	got, err := store.GetByModule(ctx, moduleID)
	if err != nil {
		t.Fatalf("GetByModule: %v", err)
	}
	if got.ID != trackID {
		t.Fatalf("GetByModule: id mismatch got %s want %s", got.ID, trackID)
	}

	_, err = store.GetByModule(ctx, uuid.New())
	if !errors.Is(err, ErrTrackNotFound) {
		t.Fatalf("GetByModule(unknown) expected ErrTrackNotFound, got %v", err)
	}
}
