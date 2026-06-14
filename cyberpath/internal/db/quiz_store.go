// Package db — quiz_store manages `quizzes` and `quiz_questions`.
// Quizzes are anchored to a lesson and/or a track; questions are children.
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Quiz mirrors a row in `quizzes`.
type Quiz struct {
	ID               uuid.UUID  `json:"id"`
	LessonID         *uuid.UUID `json:"lesson_id,omitempty"`
	TrackID          *uuid.UUID `json:"track_id,omitempty"`
	TitleSQ          string     `json:"title_sq"`
	TitleEN          string     `json:"title_en"`
	PassThreshold    int        `json:"pass_threshold"`
	TimeLimitSeconds *int       `json:"time_limit_seconds,omitempty"`
	Version          int        `json:"version"`
	ContentHash      string     `json:"content_hash"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// QuizQuestion mirrors a row in `quiz_questions`.
type QuizQuestion struct {
	ID            uuid.UUID       `json:"id"`
	QuizID        uuid.UUID       `json:"quiz_id"`
	Position      int             `json:"position"`
	Kind          string          `json:"kind"`
	PromptSQ      string          `json:"prompt_sq"`
	PromptEN      string          `json:"prompt_en"`
	Choices       json.RawMessage `json:"choices,omitempty"`
	Correct       json.RawMessage `json:"correct"`
	ExplanationSQ string          `json:"explanation_sq,omitempty"`
	ExplanationEN string          `json:"explanation_en,omitempty"`
	Points        int             `json:"points"`
}

// QuizStore wraps a pgx pool for quizzes + questions.
type QuizStore struct {
	Pool *pgxpool.Pool
}

// NewQuizStore wires a QuizStore.
func NewQuizStore(pool *pgxpool.Pool) *QuizStore { return &QuizStore{Pool: pool} }

const quizColumns = `id, lesson_id, track_id, title_sq, title_en,
	pass_threshold, time_limit_seconds, version, content_hash, created_at, updated_at`

const questionColumns = `id, quiz_id, position, kind, prompt_sq, prompt_en,
	choices, correct, explanation_sq, explanation_en, points`

func scanQuiz(row pgx.Row) (*Quiz, error) {
	var q Quiz
	if err := row.Scan(
		&q.ID, &q.LessonID, &q.TrackID, &q.TitleSQ, &q.TitleEN,
		&q.PassThreshold, &q.TimeLimitSeconds, &q.Version, &q.ContentHash,
		&q.CreatedAt, &q.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &q, nil
}

func scanQuestion(row pgx.Row) (*QuizQuestion, error) {
	var qq QuizQuestion
	var explSQ, explEN *string
	if err := row.Scan(
		&qq.ID, &qq.QuizID, &qq.Position, &qq.Kind, &qq.PromptSQ, &qq.PromptEN,
		&qq.Choices, &qq.Correct, &explSQ, &explEN, &qq.Points,
	); err != nil {
		return nil, err
	}
	if explSQ != nil {
		qq.ExplanationSQ = *explSQ
	}
	if explEN != nil {
		qq.ExplanationEN = *explEN
	}
	return &qq, nil
}

// Create inserts a quiz and its questions in a single transaction.
func (s *QuizStore) Create(ctx context.Context, q *Quiz, questions []QuizQuestion) (*Quiz, []QuizQuestion, error) {
	const op = "quiz.Create"
	if q.ID == uuid.Nil {
		q.ID = uuid.New()
	}
	if q.PassThreshold == 0 {
		q.PassThreshold = 80
	}
	if q.Version == 0 {
		q.Version = 1
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("store/%s: begin: %w", op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		INSERT INTO quizzes (
			id, lesson_id, track_id, title_sq, title_en,
			pass_threshold, time_limit_seconds, version, content_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING `+quizColumns,
		q.ID, nullableUUID(q.LessonID), nullableUUID(q.TrackID),
		q.TitleSQ, q.TitleEN, q.PassThreshold, nullableInt(q.TimeLimitSeconds),
		q.Version, q.ContentHash,
	)
	stored, err := scanQuiz(row)
	if err != nil {
		return nil, nil, fmt.Errorf("store/%s: insert quiz: %w", op, err)
	}

	out := make([]QuizQuestion, 0, len(questions))
	for _, qq := range questions {
		if qq.ID == uuid.Nil {
			qq.ID = uuid.New()
		}
		qq.QuizID = stored.ID
		if qq.Points == 0 {
			qq.Points = 1
		}
		if len(qq.Correct) == 0 {
			qq.Correct = []byte("null")
		}
		var choices any
		if len(qq.Choices) > 0 {
			choices = []byte(qq.Choices)
		}
		var explSQ, explEN any
		if qq.ExplanationSQ != "" {
			explSQ = qq.ExplanationSQ
		}
		if qq.ExplanationEN != "" {
			explEN = qq.ExplanationEN
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO quiz_questions (
				id, quiz_id, position, kind, prompt_sq, prompt_en,
				choices, correct, explanation_sq, explanation_en, points
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			RETURNING `+questionColumns,
			qq.ID, qq.QuizID, qq.Position, qq.Kind, qq.PromptSQ, qq.PromptEN,
			choices, []byte(qq.Correct), explSQ, explEN, qq.Points,
		)
		got, err := scanQuestion(row)
		if err != nil {
			return nil, nil, fmt.Errorf("store/%s: insert question pos=%d: %w", op, qq.Position, err)
		}
		out = append(out, *got)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("store/%s: commit: %w", op, err)
	}
	return stored, out, nil
}

// Get returns the quiz and its questions ordered by position.
func (s *QuizStore) Get(ctx context.Context, id uuid.UUID) (*Quiz, []QuizQuestion, error) {
	const op = "quiz.Get"
	q, err := scanQuiz(s.Pool.QueryRow(ctx, `SELECT `+quizColumns+` FROM quizzes WHERE id = $1`, id))
	if err != nil {
		return nil, nil, fmt.Errorf("store/%s: %w", op, err)
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT `+questionColumns+` FROM quiz_questions
		WHERE quiz_id = $1 ORDER BY position`, id)
	if err != nil {
		return nil, nil, fmt.Errorf("store/%s: questions: %w", op, err)
	}
	defer rows.Close()

	qs := make([]QuizQuestion, 0, 16)
	for rows.Next() {
		qq, err := scanQuestion(rows)
		if err != nil {
			return nil, nil, fmt.Errorf("store/%s: scan question: %w", op, err)
		}
		qs = append(qs, *qq)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return q, qs, nil
}

// ListByLesson returns every quiz attached to a lesson.
func (s *QuizStore) ListByLesson(ctx context.Context, lessonID uuid.UUID) ([]Quiz, error) {
	return s.listBy(ctx, "lesson_id", lessonID, "quiz.ListByLesson")
}

// ListByTrack returns every quiz attached to a track.
func (s *QuizStore) ListByTrack(ctx context.Context, trackID uuid.UUID) ([]Quiz, error) {
	return s.listBy(ctx, "track_id", trackID, "quiz.ListByTrack")
}

func (s *QuizStore) listBy(ctx context.Context, col string, id uuid.UUID, op string) ([]Quiz, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT `+quizColumns+` FROM quizzes WHERE `+col+` = $1 ORDER BY created_at`, id)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Quiz, 0, 4)
	for rows.Next() {
		q, err := scanQuiz(rows)
		if err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *q)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}
