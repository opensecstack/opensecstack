package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Incident struct {
	ID             uuid.UUID      `json:"id"`
	ConstituencyID *uuid.UUID     `json:"constituency_id"`
	Source         string         `json:"source"`
	Severity       string         `json:"severity"`
	Status         string         `json:"status"`
	Title          string         `json:"title"`
	Description    string         `json:"description,omitempty"`
	OpenedAt       time.Time      `json:"created_at"` // frontend key is created_at
	ClosedAt       *time.Time     `json:"closed_at,omitempty"`
	CitadelEmitted bool           `json:"-"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

type IncidentStore struct{ pool *pgxpool.Pool }

func NewIncidentStore(pool *pgxpool.Pool) *IncidentStore { return &IncidentStore{pool: pool} }

func (s *IncidentStore) Insert(ctx context.Context, i *Incident) error {
	if i.ID == uuid.Nil {
		i.ID = uuid.New()
	}
	if i.OpenedAt.IsZero() {
		i.OpenedAt = time.Now().UTC()
	}
	if i.Status == "" {
		i.Status = "open"
	}
	if i.Metadata == nil {
		i.Metadata = map[string]any{}
	}
	meta, err := json.Marshal(i.Metadata)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO incidents
		    (id, constituency_id, source, severity, status, title,
		     description, opened_at, closed_at, citadel_emitted, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`, i.ID, i.ConstituencyID, i.Source, i.Severity, i.Status,
		i.Title, i.Description, i.OpenedAt, i.ClosedAt, i.CitadelEmitted, meta)
	return err
}

func (s *IncidentStore) Get(ctx context.Context, id uuid.UUID) (*Incident, error) {
	i := &Incident{}
	var meta []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, constituency_id, source, severity, status, title,
		       description, opened_at, closed_at, citadel_emitted, metadata
		  FROM incidents WHERE id = $1
	`, id).Scan(&i.ID, &i.ConstituencyID, &i.Source, &i.Severity, &i.Status,
		&i.Title, &i.Description, &i.OpenedAt, &i.ClosedAt, &i.CitadelEmitted, &meta)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(meta) > 0 {
		if err := json.Unmarshal(meta, &i.Metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}
	return i, nil
}

func (s *IncidentStore) UpdateStatus(ctx context.Context, id uuid.UUID, status string, closedAt *time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE incidents
		   SET status = $2, closed_at = $3
		 WHERE id = $1
	`, id, status, closedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *IncidentStore) MarkCitadelEmitted(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE incidents SET citadel_emitted = true WHERE id = $1`, id)
	return err
}

type IncidentFilter struct {
	Status   string
	Severity string
	Limit    int
	Offset   int
}

func (s *IncidentStore) List(ctx context.Context, f IncidentFilter) ([]*Incident, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	q := `
		SELECT id, constituency_id, source, severity, status, title,
		       description, opened_at, closed_at, citadel_emitted, metadata
		  FROM incidents
		 WHERE ($1 = '' OR status = $1)
		   AND ($2 = '' OR severity = $2)
	     ORDER BY opened_at DESC, id DESC
	     LIMIT $3 OFFSET $4
	`
	rows, err := s.pool.Query(ctx, q, f.Status, f.Severity, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]*Incident, 0, f.Limit)
	for rows.Next() {
		i := &Incident{}
		var meta []byte
		if err := rows.Scan(&i.ID, &i.ConstituencyID, &i.Source, &i.Severity, &i.Status,
			&i.Title, &i.Description, &i.OpenedAt, &i.ClosedAt, &i.CitadelEmitted, &meta); err != nil {
			return nil, 0, err
		}
		if len(meta) > 0 {
			if err := json.Unmarshal(meta, &i.Metadata); err != nil {
				return nil, 0, fmt.Errorf("unmarshal metadata: %w", err)
			}
		}
		out = append(out, i)
	}
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM incidents
		 WHERE ($1 = '' OR status = $1) AND ($2 = '' OR severity = $2)
	`, f.Status, f.Severity).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count query: %w", err)
	}
	return out, total, rows.Err()
}

func (s *IncidentStore) CountByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT status, COUNT(*) FROM incidents GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}
