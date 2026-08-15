//go:build integration

// Integration tests for ProgressStore against the `progress` table.
// Requires CYBERPATH_TEST_DB_URL; skipped otherwise.
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

// progressFixture seeds a tenant, user, track, module and lesson and
// returns the ids needed to exercise ProgressStore. Cleanup cascades
// from the tenant delete.
func progressFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (userID, lessonID uuid.UUID) {
	t.Helper()

	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "pt-"+tenantID.String()[:8], "progress-test-tenant"); err != nil {
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

	trackID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tracks (id, slug, title) VALUES ($1, $2, $3)`,
		trackID, "pt-track-"+trackID.String()[:8], "Progress Test Track"); err != nil {
		t.Fatalf("seed track: %v", err)
	}

	moduleID := uuid.New()
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

	return userID, lessonID
}

func TestProgressStore_UpsertCreatesAndUpdates(t *testing.T) {
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

	userID, lessonID := progressFixture(t, ctx, pool)
	store := NewProgressStore(pool)

	created, err := store.Upsert(ctx, userID, lessonID, "", nil)
	if err != nil {
		t.Fatalf("Upsert (create): %v", err)
	}
	if created.Status != "in_progress" {
		t.Fatalf("Upsert (create): status = %q, want \"in_progress\" (default)", created.Status)
	}
	if created.CompletedAt != nil {
		t.Fatalf("Upsert (create): CompletedAt = %v, want nil", created.CompletedAt)
	}

	score := 95
	updated, err := store.Upsert(ctx, userID, lessonID, "completed", &score)
	if err != nil {
		t.Fatalf("Upsert (complete): %v", err)
	}
	if updated.ID != created.ID {
		t.Fatalf("Upsert (complete): expected same row id, got %v vs %v", updated.ID, created.ID)
	}
	if updated.Status != "completed" {
		t.Fatalf("Upsert (complete): status = %q, want \"completed\"", updated.Status)
	}
	if updated.Score == nil || *updated.Score != 95 {
		t.Fatalf("Upsert (complete): score = %v, want 95", updated.Score)
	}
	if updated.CompletedAt == nil {
		t.Fatal("Upsert (complete): CompletedAt not set")
	}
	firstCompletedAt := *updated.CompletedAt

	// Re-upserting completed again must not clobber completed_at.
	again, err := store.Upsert(ctx, userID, lessonID, "completed", nil)
	if err != nil {
		t.Fatalf("Upsert (re-complete): %v", err)
	}
	if again.CompletedAt == nil || !again.CompletedAt.Equal(firstCompletedAt) {
		t.Fatalf("Upsert (re-complete): CompletedAt changed: got %v, want %v", again.CompletedAt, firstCompletedAt)
	}
	// score not passed (nil) should be preserved via COALESCE.
	if again.Score == nil || *again.Score != 95 {
		t.Fatalf("Upsert (re-complete): score = %v, want preserved 95", again.Score)
	}
}

func TestProgressStore_GetByUserAndLesson(t *testing.T) {
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

	userID, lessonID := progressFixture(t, ctx, pool)
	store := NewProgressStore(pool)

	if _, err := store.Upsert(ctx, userID, lessonID, "in_progress", nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := store.GetByUserAndLesson(ctx, userID, lessonID)
	if err != nil {
		t.Fatalf("GetByUserAndLesson: %v", err)
	}
	if got.UserID != userID || got.LessonID != lessonID {
		t.Fatalf("GetByUserAndLesson: unexpected row %+v", got)
	}

	_, err = store.GetByUserAndLesson(ctx, userID, uuid.New())
	if !errors.Is(err, ErrProgressNotFound) {
		t.Fatalf("GetByUserAndLesson (missing): err = %v, want ErrProgressNotFound", err)
	}
}

func TestProgressStore_GetByUser(t *testing.T) {
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

	userID, lessonID := progressFixture(t, ctx, pool)
	store := NewProgressStore(pool)

	if _, err := store.Upsert(ctx, userID, lessonID, "in_progress", nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	list, err := store.GetByUser(ctx, userID)
	if err != nil {
		t.Fatalf("GetByUser: %v", err)
	}
	if len(list) != 1 || list[0].LessonID != lessonID {
		t.Fatalf("GetByUser: expected 1 row for our lesson, got %d", len(list))
	}

	empty, err := store.GetByUser(ctx, uuid.New())
	if err != nil {
		t.Fatalf("GetByUser (unknown user): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("GetByUser (unknown user): got %d rows, want 0", len(empty))
	}
}
