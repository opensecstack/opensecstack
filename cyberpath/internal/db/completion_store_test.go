//go:build integration

// Integration tests for CompletionStore against the `completions` table.
// Requires CYBERPATH_TEST_DB_URL; skipped otherwise.
package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// completionFixture seeds a tenant, user, track, module and lesson.
func completionFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (userID, trackID, moduleID, lessonID uuid.UUID) {
	t.Helper()

	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "ct-"+tenantID.String()[:8], "completion-test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	userID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		userID, tenantID, userID.String()+"@test.local"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	trackID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tracks (id, slug, title) VALUES ($1, $2, $3)`,
		trackID, "ct-track-"+trackID.String()[:8], "Completion Test Track"); err != nil {
		t.Fatalf("seed track: %v", err)
	}

	moduleID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO modules (id, track_id, slug, title) VALUES ($1, $2, 'mod', 'Module')`,
		moduleID, trackID); err != nil {
		t.Fatalf("seed module: %v", err)
	}

	lessonID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO lessons (id, module_id, slug, title) VALUES ($1, $2, 'lesson', 'Lesson')`,
		lessonID, moduleID); err != nil {
		t.Fatalf("seed lesson: %v", err)
	}

	return userID, trackID, moduleID, lessonID
}

func TestCompletionStore_CreateIsIdempotent(t *testing.T) {
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

	userID, _, _, lessonID := completionFixture(t, ctx, pool)
	store := NewCompletionStore(pool)

	score := 80
	first, err := store.Create(ctx, userID, "lesson", lessonID, &score, "corr-1", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if first.Score == nil || *first.Score != 80 {
		t.Fatalf("Create: score = %v, want 80", first.Score)
	}
	if first.CorrelationID != "corr-1" {
		t.Fatalf("Create: correlation_id = %q, want \"corr-1\"", first.CorrelationID)
	}

	// Second call with the same (user, kind, target) hits ON CONFLICT.
	// Per the doc comment, score is COALESCE'd from EXCLUDED (so a new
	// non-nil score overwrites), but content_version_id is first-write-wins.
	newScore := 100
	second, err := store.Create(ctx, userID, "lesson", lessonID, &newScore, "corr-2", nil)
	if err != nil {
		t.Fatalf("Create (conflict): %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("Create (conflict): expected same row id, got %v vs %v", second.ID, first.ID)
	}
	if second.Score == nil || *second.Score != 100 {
		t.Fatalf("Create (conflict): score = %v, want overwritten to 100", second.Score)
	}

	list, err := store.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListByUser: got %d rows, want 1 (idempotent create)", len(list))
	}
}

func TestCompletionStore_ListByTrack(t *testing.T) {
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

	userID, trackID, _, _ := completionFixture(t, ctx, pool)
	store := NewCompletionStore(pool)

	if _, err := store.Create(ctx, userID, "track", trackID, nil, "", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}

	list, err := store.ListByTrack(ctx, trackID)
	if err != nil {
		t.Fatalf("ListByTrack: %v", err)
	}
	if len(list) != 1 || list[0].TargetID != trackID || list[0].Kind != "track" {
		t.Fatalf("ListByTrack: unexpected results %+v", list)
	}

	empty, err := store.ListByTrack(ctx, uuid.New())
	if err != nil {
		t.Fatalf("ListByTrack (unknown): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListByTrack (unknown): got %d, want 0", len(empty))
	}
}

func TestCompletionStore_AllLessonsCompletedForTrack(t *testing.T) {
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

	userID, trackID, moduleID, lessonID := completionFixture(t, ctx, pool)
	store := NewCompletionStore(pool)

	// Not yet completed: false.
	done, err := store.AllLessonsCompletedForTrack(ctx, userID, trackID)
	if err != nil {
		t.Fatalf("AllLessonsCompletedForTrack (before): %v", err)
	}
	if done {
		t.Fatal("AllLessonsCompletedForTrack (before): expected false, no completions yet")
	}

	// Add a second lesson so we can prove partial completion is still false.
	lesson2ID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO lessons (id, module_id, slug, title) VALUES ($1, $2, 'lesson-2', 'Lesson 2')`,
		lesson2ID, moduleID); err != nil {
		t.Fatalf("seed lesson2: %v", err)
	}

	if _, err := store.Create(ctx, userID, "lesson", lessonID, nil, "", nil); err != nil {
		t.Fatalf("Create (lesson1): %v", err)
	}

	done, err = store.AllLessonsCompletedForTrack(ctx, userID, trackID)
	if err != nil {
		t.Fatalf("AllLessonsCompletedForTrack (partial): %v", err)
	}
	if done {
		t.Fatal("AllLessonsCompletedForTrack (partial): expected false, only 1 of 2 lessons done")
	}

	if _, err := store.Create(ctx, userID, "lesson", lesson2ID, nil, "", nil); err != nil {
		t.Fatalf("Create (lesson2): %v", err)
	}

	done, err = store.AllLessonsCompletedForTrack(ctx, userID, trackID)
	if err != nil {
		t.Fatalf("AllLessonsCompletedForTrack (complete): %v", err)
	}
	if !done {
		t.Fatal("AllLessonsCompletedForTrack (complete): expected true, both lessons done")
	}
}

func TestCompletionStore_AllLessonsCompletedForTrack_NoLessons(t *testing.T) {
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

	store := NewCompletionStore(pool)

	// A track with zero lessons must report false, not true (EXISTS guard).
	done, err := store.AllLessonsCompletedForTrack(ctx, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("AllLessonsCompletedForTrack: %v", err)
	}
	if done {
		t.Fatal("AllLessonsCompletedForTrack: expected false for a track with no lessons")
	}
}
