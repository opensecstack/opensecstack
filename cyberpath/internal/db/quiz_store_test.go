//go:build integration

// Integration tests for QuizStore. Requires CYBERPATH_TEST_DB_URL pointing at
// a fully-migrated cyberpath schema; otherwise skipped.
package db

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func quizTestPool(t *testing.T) *pgxpool.Pool {
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

// seedQuizTrack inserts a bare track row and registers cleanup.
func seedQuizTrack(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tracks (id, slug, title) VALUES ($1, $2, $3)`,
		id, "qz-trk-"+id.String()[:8], "Quiz Track"); err != nil {
		t.Fatalf("seed track: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tracks WHERE id = $1`, id)
	})
	return id
}

// seedQuizLesson inserts a track + module + lesson chain and registers cleanup.
func seedQuizLesson(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	trackID := seedQuizTrack(t, pool)

	moduleID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO modules (id, track_id, slug, title) VALUES ($1, $2, 'm1', 'Module 1')`,
		moduleID, trackID); err != nil {
		t.Fatalf("seed module: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM modules WHERE id = $1`, moduleID) })

	lessonID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO lessons (id, module_id, slug, title) VALUES ($1, $2, 'l1', 'Lesson 1')`,
		lessonID, moduleID); err != nil {
		t.Fatalf("seed lesson: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM lessons WHERE id = $1`, lessonID) })
	return lessonID
}

func cleanupQuiz(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM quizzes WHERE id = $1`, id)
	})
}

func TestQuizStore_CreateAndGet(t *testing.T) {
	pool := quizTestPool(t)
	ctx := context.Background()
	trackID := seedQuizTrack(t, pool)
	store := NewQuizStore(pool)

	q := &Quiz{
		TrackID: &trackID,
		TitleSQ: "Kuiz",
		TitleEN: "Quiz",
	}
	questions := []QuizQuestion{
		{
			Position: 1,
			Kind:     "true_false",
			PromptSQ: "E vertete?",
			PromptEN: "True?",
			Correct:  json.RawMessage(`true`),
		},
		{
			Position: 2,
			Kind:     "multiple_choice",
			PromptSQ: "Zgjidh",
			PromptEN: "Pick one",
			Choices:  json.RawMessage(`[{"id":"a","text_en":"A"},{"id":"b","text_en":"B"}]`),
			Correct:  json.RawMessage(`["a"]`),
			Points:   5,
		},
	}

	stored, storedQs, err := store.Create(ctx, q, questions)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanupQuiz(t, pool, stored.ID)

	if stored.ID == uuid.Nil {
		t.Fatal("Create: quiz id not populated")
	}
	if stored.PassThreshold != 80 {
		t.Fatalf("Create: expected default pass_threshold 80, got %d", stored.PassThreshold)
	}
	if stored.Version != 1 {
		t.Fatalf("Create: expected default version 1, got %d", stored.Version)
	}
	if len(storedQs) != 2 {
		t.Fatalf("Create: expected 2 questions, got %d", len(storedQs))
	}
	if storedQs[1].Points != 5 {
		t.Fatalf("Create: points not persisted, got %d", storedQs[1].Points)
	}
	if storedQs[0].Points != 1 {
		t.Fatalf("Create: expected default points 1, got %d", storedQs[0].Points)
	}
	for _, qq := range storedQs {
		if qq.QuizID != stored.ID {
			t.Fatalf("Create: question.QuizID not linked: %+v", qq)
		}
	}

	gotQuiz, gotQs, err := store.Get(ctx, stored.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotQuiz.TitleEN != "Quiz" {
		t.Fatalf("Get: title mismatch: %+v", gotQuiz)
	}
	if len(gotQs) != 2 {
		t.Fatalf("Get: expected 2 questions, got %d", len(gotQs))
	}
	if gotQs[0].Position != 1 || gotQs[1].Position != 2 {
		t.Fatalf("Get: questions not ordered by position: %+v", gotQs)
	}
}

func TestQuizStore_Create_RequiresAnchor(t *testing.T) {
	pool := quizTestPool(t)
	ctx := context.Background()
	store := NewQuizStore(pool)

	// Neither lesson_id nor track_id set -> violates quizzes_anchor_chk.
	_, _, err := store.Create(ctx, &Quiz{TitleEN: "Orphan"}, nil)
	if err == nil {
		t.Fatal("Create with no anchor: expected CHECK violation, got nil")
	}
}

func TestQuizStore_Create_RollsBackOnBadQuestion(t *testing.T) {
	pool := quizTestPool(t)
	ctx := context.Background()
	trackID := seedQuizTrack(t, pool)
	store := NewQuizStore(pool)

	q := &Quiz{TrackID: &trackID, TitleEN: "Broken"}
	questions := []QuizQuestion{
		{Position: 1, Kind: "not-a-real-kind", PromptEN: "bad", Correct: json.RawMessage(`true`)},
	}
	_, _, err := store.Create(ctx, q, questions)
	if err == nil {
		t.Fatal("Create with invalid question kind: expected CHECK violation, got nil")
	}

	// The quiz insert must have been rolled back along with the question.
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM quizzes WHERE id = $1`, q.ID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatal("Create: quiz row survived a failed transaction (rollback did not happen)")
	}
}

func TestQuizStore_Get_NotFound(t *testing.T) {
	pool := quizTestPool(t)
	ctx := context.Background()
	store := NewQuizStore(pool)

	_, _, err := store.Get(ctx, uuid.New())
	if err == nil {
		t.Fatal("Get(unknown id): expected error, got nil")
	}
}

func TestQuizStore_ListByLessonAndTrack(t *testing.T) {
	pool := quizTestPool(t)
	ctx := context.Background()
	trackID := seedQuizTrack(t, pool)
	lessonID := seedQuizLesson(t, pool)
	store := NewQuizStore(pool)

	trackQuiz, _, err := store.Create(ctx, &Quiz{TrackID: &trackID, TitleEN: "Track Quiz"}, nil)
	if err != nil {
		t.Fatalf("Create track quiz: %v", err)
	}
	cleanupQuiz(t, pool, trackQuiz.ID)

	lessonQuiz, _, err := store.Create(ctx, &Quiz{LessonID: &lessonID, TitleEN: "Lesson Quiz"}, nil)
	if err != nil {
		t.Fatalf("Create lesson quiz: %v", err)
	}
	cleanupQuiz(t, pool, lessonQuiz.ID)

	byTrack, err := store.ListByTrack(ctx, trackID)
	if err != nil {
		t.Fatalf("ListByTrack: %v", err)
	}
	if len(byTrack) != 1 || byTrack[0].ID != trackQuiz.ID {
		t.Fatalf("ListByTrack: expected only the track quiz, got %+v", byTrack)
	}

	byLesson, err := store.ListByLesson(ctx, lessonID)
	if err != nil {
		t.Fatalf("ListByLesson: %v", err)
	}
	if len(byLesson) != 1 || byLesson[0].ID != lessonQuiz.ID {
		t.Fatalf("ListByLesson: expected only the lesson quiz, got %+v", byLesson)
	}
}
