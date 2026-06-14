// Package db — completion_store manages the `completions` table
// (track-/module-/lesson-level milestones).
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Completion mirrors a row in `completions`.
type Completion struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	Kind             string     `json:"kind"`
	TargetID         uuid.UUID  `json:"target_id"`
	Score            *int       `json:"score,omitempty"`
	CompletedAt      time.Time  `json:"completed_at"`
	CorrelationID    string     `json:"correlation_id,omitempty"`
	ContentVersionID *uuid.UUID `json:"content_version_id,omitempty"`
}

// CompletionStore wraps a pgx pool for `completions`.
type CompletionStore struct {
	Pool *pgxpool.Pool
}

// NewCompletionStore wires a CompletionStore.
func NewCompletionStore(pool *pgxpool.Pool) *CompletionStore { return &CompletionStore{Pool: pool} }

const completionColumns = `id, user_id, kind, target_id, score, completed_at,
	COALESCE(correlation_id, ''), content_version_id`

func scanCompletion(row pgx.Row) (*Completion, error) {
	var c Completion
	if err := row.Scan(
		&c.ID, &c.UserID, &c.Kind, &c.TargetID, &c.Score, &c.CompletedAt, &c.CorrelationID,
		&c.ContentVersionID,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

// Create inserts a completion row. Idempotent on (user_id, kind, target_id):
// returns the existing row when the unique constraint fires. On conflict the
// content_version_id is preserved (first write wins — immutable audit chain).
func (s *CompletionStore) Create(ctx context.Context, userID uuid.UUID, kind string, targetID uuid.UUID, score *int, correlationID string, contentVersionID *uuid.UUID) (*Completion, error) {
	const op = "db/completion_store/Create"
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO completions (user_id, kind, target_id, score, correlation_id, content_version_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, kind, target_id) DO UPDATE
		SET score = COALESCE(EXCLUDED.score, completions.score),
		    content_version_id = COALESCE(completions.content_version_id, EXCLUDED.content_version_id)
		RETURNING `+completionColumns,
		userID, kind, targetID, nullableInt(score), nullableString(correlationID), nullableUUID(contentVersionID),
	)
	c, err := scanCompletion(row)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return c, nil
}

// ListByUser returns every completion for a user, newest first.
func (s *CompletionStore) ListByUser(ctx context.Context, userID uuid.UUID) ([]Completion, error) {
	return s.listBy(ctx, "user_id = $1", []any{userID}, "db/completion_store/ListByUser")
}

// ListByTrack returns every track-kind completion for a track, newest first.
func (s *CompletionStore) ListByTrack(ctx context.Context, trackID uuid.UUID) ([]Completion, error) {
	return s.listBy(ctx, "kind = 'track' AND target_id = $1", []any{trackID}, "db/completion_store/ListByTrack")
}

// AllLessonsCompletedForTrack reports true when every lesson in the track has
// a completion row for userID. Returns false (not an error) when the track
// has no lessons or when at least one lesson has no completion record.
func (s *CompletionStore) AllLessonsCompletedForTrack(ctx context.Context, userID, trackID uuid.UUID) (bool, error) {
	const op = "db/completion_store/AllLessonsCompletedForTrack"
	var done bool
	err := s.Pool.QueryRow(ctx, `
		SELECT
			EXISTS(SELECT 1 FROM lessons l JOIN modules m ON m.id = l.module_id WHERE m.track_id = $2)
			AND NOT EXISTS(
				SELECT 1 FROM lessons l
				JOIN modules m ON m.id = l.module_id
				WHERE m.track_id = $2
				  AND NOT EXISTS(
					SELECT 1 FROM completions c
					WHERE c.user_id = $1 AND c.kind = 'lesson' AND c.target_id = l.id
				  )
			)`, userID, trackID,
	).Scan(&done)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return done, nil
}

func (s *CompletionStore) listBy(ctx context.Context, where string, args []any, op string) ([]Completion, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT `+completionColumns+` FROM completions WHERE `+where+` ORDER BY completed_at DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Completion, 0, 16)
	for rows.Next() {
		c, err := scanCompletion(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		out = append(out, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows: %w", op, err)
	}
	return out, nil
}
