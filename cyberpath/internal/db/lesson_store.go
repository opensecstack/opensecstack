// Package db — lesson_store manages the `lessons` table.
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

// Lesson mirrors a row in `lessons`.
type Lesson struct {
	ID          uuid.UUID `json:"id"`
	ModuleID    uuid.UUID `json:"module_id"`
	Slug        string    `json:"slug"`
	Title       string    `json:"title"`
	Locale      string    `json:"locale"`
	BodyMD      string    `json:"body_md"`
	Order       int       `json:"order"`
	DurationMin int       `json:"duration_min"`
	CreatedAt   time.Time `json:"created_at"`
}

// LessonStore wraps a pgx pool for `lessons`.
type LessonStore struct {
	Pool *pgxpool.Pool
}

// NewLessonStore wires a LessonStore.
func NewLessonStore(pool *pgxpool.Pool) *LessonStore { return &LessonStore{Pool: pool} }

// ErrLessonNotFound is returned when no row matches a Get lookup.
var ErrLessonNotFound = errors.New("db/lesson_store: lesson not found")

const lessonColumns = `id, module_id, slug, title, locale, body_md,
	ord, duration_min, created_at`

func scanLesson(row pgx.Row) (*Lesson, error) {
	var l Lesson
	if err := row.Scan(
		&l.ID, &l.ModuleID, &l.Slug, &l.Title, &l.Locale, &l.BodyMD,
		&l.Order, &l.DurationMin, &l.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &l, nil
}

// Get returns a lesson by id.
func (s *LessonStore) Get(ctx context.Context, id uuid.UUID) (*Lesson, error) {
	const op = "db/lesson_store/Get"
	row := s.Pool.QueryRow(ctx, `SELECT `+lessonColumns+` FROM lessons WHERE id = $1`, id)
	l, err := scanLesson(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, ErrLessonNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return l, nil
}

// ListByModule returns lessons for a module ordered by ord.
func (s *LessonStore) ListByModule(ctx context.Context, moduleID uuid.UUID) ([]Lesson, error) {
	const op = "db/lesson_store/ListByModule"
	rows, err := s.Pool.Query(ctx, `
		SELECT `+lessonColumns+` FROM lessons
		WHERE module_id = $1
		ORDER BY ord, slug`, moduleID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Lesson, 0, 16)
	for rows.Next() {
		l, err := scanLesson(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		out = append(out, *l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows: %w", op, err)
	}
	return out, nil
}

// ListByTrack returns all lessons in a track joined via modules,
// ordered by module.ord then lesson.ord.
func (s *LessonStore) ListByTrack(ctx context.Context, trackID uuid.UUID) ([]Lesson, error) {
	const op = "db/lesson_store/ListByTrack"
	rows, err := s.Pool.Query(ctx, `
		SELECT l.id, l.module_id, l.slug, l.title, l.locale, l.body_md,
		       l.ord, l.duration_min, l.created_at
		FROM lessons l
		JOIN modules m ON m.id = l.module_id
		WHERE m.track_id = $1
		ORDER BY m.ord, l.ord, l.slug`, trackID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Lesson, 0, 32)
	for rows.Next() {
		l, err := scanLesson(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		out = append(out, *l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows: %w", op, err)
	}
	return out, nil
}
