// Package db — progress_store manages the `progress` table
// (per-user, per-lesson tracking).
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Progress mirrors a row in `progress`.
type Progress struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	LessonID    uuid.UUID  `json:"lesson_id"`
	Status      string     `json:"status"`
	Score       *int       `json:"score,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// ProgressStore wraps a pgx pool for `progress`.
type ProgressStore struct {
	Pool *pgxpool.Pool
}

// NewProgressStore wires a ProgressStore.
func NewProgressStore(pool *pgxpool.Pool) *ProgressStore { return &ProgressStore{Pool: pool} }

// ErrProgressNotFound is returned when no row matches a Get lookup.
var ErrProgressNotFound = errors.New("db/progress_store: progress not found")

const progressColumns = `id, user_id, lesson_id, status, score, started_at, completed_at`

func scanProgress(row pgx.Row) (*Progress, error) {
	var p Progress
	if err := row.Scan(
		&p.ID, &p.UserID, &p.LessonID, &p.Status, &p.Score, &p.StartedAt, &p.CompletedAt,
	); err != nil {
		return nil, err
	}
	return &p, nil
}

// Upsert creates or updates a progress row keyed by (user_id, lesson_id).
// When status="completed" completed_at is set to now().
func (s *ProgressStore) Upsert(ctx context.Context, userID, lessonID uuid.UUID, status string, score *int) (*Progress, error) {
	const op = "db/progress_store/Upsert"
	if status == "" {
		status = "in_progress"
	}
	completedExpr := "NULL::timestamptz"
	if status == "completed" {
		completedExpr = "now()"
	}
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO progress (user_id, lesson_id, status, score, completed_at)
		VALUES ($1, $2, $3, $4, `+completedExpr+`)
		ON CONFLICT (user_id, lesson_id) DO UPDATE
		SET status = EXCLUDED.status,
		    score = COALESCE(EXCLUDED.score, progress.score),
		    completed_at = CASE WHEN EXCLUDED.status = 'completed'
		                        THEN COALESCE(progress.completed_at, now())
		                        ELSE progress.completed_at END
		RETURNING `+progressColumns,
		userID, lessonID, status, nullableInt(score),
	)
	p, err := scanProgress(row)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return p, nil
}

// GetByUser returns all progress rows for a user.
func (s *ProgressStore) GetByUser(ctx context.Context, userID uuid.UUID) ([]Progress, error) {
	const op = "db/progress_store/GetByUser"
	rows, err := s.Pool.Query(ctx, `
		SELECT `+progressColumns+` FROM progress
		WHERE user_id = $1
		ORDER BY started_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Progress, 0, 32)
	for rows.Next() {
		p, err := scanProgress(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		out = append(out, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows: %w", op, err)
	}
	return out, nil
}

// GetByUserAndLesson returns the single progress row for a user+lesson,
// or ErrProgressNotFound.
func (s *ProgressStore) GetByUserAndLesson(ctx context.Context, userID, lessonID uuid.UUID) (*Progress, error) {
	const op = "db/progress_store/GetByUserAndLesson"
	row := s.Pool.QueryRow(ctx, `
		SELECT `+progressColumns+` FROM progress
		WHERE user_id = $1 AND lesson_id = $2`, userID, lessonID)
	p, err := scanProgress(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, ErrProgressNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return p, nil
}
