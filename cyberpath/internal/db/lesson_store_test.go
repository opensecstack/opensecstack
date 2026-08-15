//go:build integration

// Integration tests for LessonStore against the `lessons` table.
// LessonStore is read-only (Get/ListByModule/ListByTrack); rows are
// seeded here with raw SQL since there is no Create method on the store
// itself. Requires CYBERPATH_TEST_DB_URL; skipped otherwise.
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

func TestLessonStore_GetAndLists(t *testing.T) {
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
		trackID, "lestest-"+trackID.String()[:8], "Lesson Test Track"); err != nil {
		t.Fatalf("seed track: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tracks WHERE id = $1`, trackID)
	})

	moduleID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO modules (id, track_id, slug, title, ord) VALUES ($1, $2, 'mod-1', 'Module 1', 0)`,
		moduleID, trackID); err != nil {
		t.Fatalf("seed module: %v", err)
	}

	lesson1ID := uuid.New()
	lesson2ID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO lessons (id, module_id, slug, title, locale, body_md, ord, duration_min) VALUES
			($1, $3, 'intro', 'Intro', 'en', 'body one', 1, 5),
			($2, $3, 'basics', 'Basics', 'en', 'body two', 0, 10)`,
		lesson1ID, lesson2ID, moduleID); err != nil {
		t.Fatalf("seed lessons: %v", err)
	}

	store := NewLessonStore(pool)

	got, err := store.Get(ctx, lesson1ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Slug != "intro" || got.Title != "Intro" || got.DurationMin != 5 || got.Order != 1 {
		t.Fatalf("Get: unexpected lesson %+v", got)
	}
	if got.ModuleID != moduleID {
		t.Fatalf("Get: module_id = %v, want %v", got.ModuleID, moduleID)
	}

	byModule, err := store.ListByModule(ctx, moduleID)
	if err != nil {
		t.Fatalf("ListByModule: %v", err)
	}
	if len(byModule) != 2 {
		t.Fatalf("ListByModule: got %d lessons, want 2", len(byModule))
	}
	// ORDER BY ord, slug: basics (ord=0) before intro (ord=1).
	if byModule[0].Slug != "basics" || byModule[1].Slug != "intro" {
		t.Fatalf("ListByModule: wrong order: %q, %q", byModule[0].Slug, byModule[1].Slug)
	}

	byTrack, err := store.ListByTrack(ctx, trackID)
	if err != nil {
		t.Fatalf("ListByTrack: %v", err)
	}
	if len(byTrack) != 2 {
		t.Fatalf("ListByTrack: got %d lessons, want 2", len(byTrack))
	}
}

func TestLessonStore_Get_NotFound(t *testing.T) {
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

	store := NewLessonStore(pool)

	_, err = store.Get(ctx, uuid.New())
	if !errors.Is(err, ErrLessonNotFound) {
		t.Fatalf("Get: err = %v, want ErrLessonNotFound", err)
	}
}

func TestLessonStore_ListByTrack_Empty(t *testing.T) {
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

	store := NewLessonStore(pool)

	list, err := store.ListByTrack(ctx, uuid.New())
	if err != nil {
		t.Fatalf("ListByTrack: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListByTrack: got %d lessons for unknown track, want 0", len(list))
	}
}
