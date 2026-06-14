// Package db — module_store manages the `modules` table.
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

// Module mirrors a row in `modules`.
type Module struct {
	ID        uuid.UUID `json:"id"`
	TrackID   uuid.UUID `json:"track_id"`
	Slug      string    `json:"slug"`
	Title     string    `json:"title"`
	Order     int       `json:"order"`
	CreatedAt time.Time `json:"created_at"`
}

// ModuleStore wraps a pgx pool for `modules`.
type ModuleStore struct {
	Pool *pgxpool.Pool
}

// NewModuleStore wires a ModuleStore.
func NewModuleStore(pool *pgxpool.Pool) *ModuleStore { return &ModuleStore{Pool: pool} }

// ErrModuleNotFound is returned when no row matches a Get lookup.
var ErrModuleNotFound = errors.New("db/module_store: module not found")

const moduleColumns = `id, track_id, slug, title, ord, created_at`

func scanModule(row pgx.Row) (*Module, error) {
	var m Module
	if err := row.Scan(
		&m.ID, &m.TrackID, &m.Slug, &m.Title, &m.Order, &m.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &m, nil
}

// Get returns a module by id.
func (s *ModuleStore) Get(ctx context.Context, id uuid.UUID) (*Module, error) {
	const op = "db/module_store/Get"
	row := s.Pool.QueryRow(ctx, `SELECT `+moduleColumns+` FROM modules WHERE id = $1`, id)
	m, err := scanModule(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s: %w", op, ErrModuleNotFound)
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return m, nil
}

// ListByTrack returns modules for a track ordered by ord.
func (s *ModuleStore) ListByTrack(ctx context.Context, trackID uuid.UUID) ([]Module, error) {
	const op = "db/module_store/ListByTrack"
	rows, err := s.Pool.Query(ctx, `
		SELECT `+moduleColumns+` FROM modules
		WHERE track_id = $1
		ORDER BY ord, slug`, trackID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Module, 0, 8)
	for rows.Next() {
		m, err := scanModule(rows)
		if err != nil {
			return nil, fmt.Errorf("%s: scan: %w", op, err)
		}
		out = append(out, *m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: rows: %w", op, err)
	}
	return out, nil
}
