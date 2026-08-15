// Package db — track_store manages the `tracks` table.
// Read-only API for the v1.0.0 handlers; writes flow through
// internal/content/publisher.go via raw SQL.
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

// Track mirrors a row in `tracks`.
type Track struct {
	ID          uuid.UUID `json:"id"`
	Slug        string    `json:"slug"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Locale      string    `json:"locale"`
	Difficulty  string    `json:"difficulty"`
	Tags        []string  `json:"tags"`
	NIS2Refs    []string  `json:"nis2_refs"`
	Published   bool      `json:"published"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TrackFilter narrows ListTracks results.
type TrackFilter struct {
	Published *bool
	Locale    string
	Limit     int
	Offset    int
}

// TrackStore wraps a pgx pool for `tracks`.
type TrackStore struct {
	Pool *pgxpool.Pool
}

// NewTrackStore wires a TrackStore.
func NewTrackStore(pool *pgxpool.Pool) *TrackStore { return &TrackStore{Pool: pool} }

// ErrTrackNotFound is returned when no row matches a Get lookup.
var ErrTrackNotFound = errors.New("db/track_store: track not found")

const trackColumns = `id, slug, title, description, locale, difficulty,
	tags, nis2_refs, published, created_at, updated_at`

func scanTrack(row pgx.Row) (*Track, error) {
	var t Track
	if err := row.Scan(
		&t.ID, &t.Slug, &t.Title, &t.Description, &t.Locale, &t.Difficulty,
		&t.Tags, &t.NIS2Refs, &t.Published, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &t, nil
}

// Get returns a track by id.
func (s *TrackStore) Get(ctx context.Context, id uuid.UUID) (*Track, error) {
	const op = "db/track_store/Get"
	row := s.Pool.QueryRow(ctx, `SELECT `+trackColumns+` FROM tracks WHERE id = $1`, id)
	t, err := scanTrack(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, ErrTrackNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return t, nil
}

// GetBySlug returns a track by slug (used by /tracks/{id} when id is a slug).
func (s *TrackStore) GetBySlug(ctx context.Context, slug string) (*Track, error) {
	const op = "db/track_store/GetBySlug"
	row := s.Pool.QueryRow(ctx, `SELECT `+trackColumns+` FROM tracks WHERE slug = $1`, slug)
	t, err := scanTrack(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, ErrTrackNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return t, nil
}

// List returns tracks matching the filter, ordered by slug.
func (s *TrackStore) List(ctx context.Context, f TrackFilter) ([]Track, error) {
	const op = "db/track_store/List"
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args := []any{}
	q := `SELECT ` + trackColumns + ` FROM tracks`
	conds := ""
	if f.Published != nil {
		args = append(args, *f.Published)
		conds += fmt.Sprintf(" WHERE published = $%d", len(args))
	}
	if f.Locale != "" {
		args = append(args, f.Locale)
		if conds == "" {
			conds = fmt.Sprintf(" WHERE locale = $%d", len(args))
		} else {
			conds += fmt.Sprintf(" AND locale = $%d", len(args))
		}
	}
	q += conds + fmt.Sprintf(" ORDER BY slug LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, f.Offset)

	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Track, 0, 16)
	for rows.Next() {
		t, err := scanTrack(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		out = append(out, *t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows: %w", op, err)
	}
	return out, nil
}

// ListPublished is a convenience wrapper for ListPublished tracks.
func (s *TrackStore) ListPublished(ctx context.Context) ([]Track, error) {
	pub := true
	return s.List(ctx, TrackFilter{Published: &pub})
}

// GetByModule returns the track that owns the given module id.
func (s *TrackStore) GetByModule(ctx context.Context, moduleID uuid.UUID) (*Track, error) {
	const op = "db/track_store/GetByModule"
	row := s.Pool.QueryRow(ctx, `
		SELECT t.id, t.slug, t.title, t.description, t.locale, t.difficulty,
		       t.tags, t.nis2_refs, t.published, t.created_at, t.updated_at
		FROM tracks t
		JOIN modules m ON m.track_id = t.id
		WHERE m.id = $1`, moduleID)
	t, err := scanTrack(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, ErrTrackNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return t, nil
}
