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

type Advisory struct {
	ID             uuid.UUID      `json:"id"`
	IncidentID     *uuid.UUID     `json:"incident_id"`
	CSAFID         string         `json:"csaf_id"`
	CSAFVersion    string         `json:"-"` // CSAF spec version "2.0", not advisory revision
	CSAFDoc        map[string]any `json:"-"` // served via /advisories/{id}/csaf
	State          string         `json:"state"`
	TLP            string         `json:"tlp"` // lowercase: clear|green|amber|red
	Title          string         `json:"title"`
	Summary        string         `json:"summary"`
	Revision       int            `json:"version"` // advisory revision counter, starts at 1
	PublishedAt    *time.Time     `json:"published_at"`
	WithdrawnAt    *time.Time     `json:"withdrawn_at"`
	PublishedBy    *uuid.UUID     `json:"-"`
	CitadelEmitted bool           `json:"-"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type AdvisoryStore struct{ pool *pgxpool.Pool }

func NewAdvisoryStore(pool *pgxpool.Pool) *AdvisoryStore { return &AdvisoryStore{pool: pool} }

func (s *AdvisoryStore) Insert(ctx context.Context, a *Advisory) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.CSAFVersion == "" {
		a.CSAFVersion = "2.0"
	}
	if a.State == "" {
		a.State = "draft"
	}
	if a.TLP == "" {
		a.TLP = "green"
	}
	now := time.Now().UTC()
	a.CreatedAt = now
	a.UpdatedAt = now
	doc, err := json.Marshal(a.CSAFDoc)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO advisories
		    (id, incident_id, csaf_id, csaf_version, csaf_doc, state, tlp,
		     title, summary, revision, published_at, withdrawn_at,
		     published_by, citadel_emitted, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
	`, a.ID, a.IncidentID, a.CSAFID, a.CSAFVersion, doc, a.State, a.TLP,
		a.Title, a.Summary, 1, a.PublishedAt, a.WithdrawnAt,
		a.PublishedBy, a.CitadelEmitted, a.CreatedAt, a.UpdatedAt)
	return err
}

func (s *AdvisoryStore) Get(ctx context.Context, id uuid.UUID) (*Advisory, error) {
	a := &Advisory{}
	var doc []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, incident_id, csaf_id, csaf_version, csaf_doc, state, tlp,
		       title, summary, revision, published_at, withdrawn_at,
		       published_by, citadel_emitted, created_at, updated_at
		  FROM advisories WHERE id = $1
	`, id).Scan(&a.ID, &a.IncidentID, &a.CSAFID, &a.CSAFVersion, &doc, &a.State, &a.TLP,
		&a.Title, &a.Summary, &a.Revision, &a.PublishedAt, &a.WithdrawnAt,
		&a.PublishedBy, &a.CitadelEmitted, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(doc) > 0 {
		if err := json.Unmarshal(doc, &a.CSAFDoc); err != nil {
			return nil, fmt.Errorf("unmarshal csaf_doc: %w", err)
		}
	}
	return a, nil
}

func (s *AdvisoryStore) Publish(ctx context.Context, id, by uuid.UUID) error {
	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE advisories
		   SET state = 'published', published_at = $2, published_by = $3,
		       revision = revision + 1, updated_at = $2
		 WHERE id = $1 AND state = 'draft'
	`, id, now, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *AdvisoryStore) Withdraw(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE advisories
		   SET state = 'withdrawn', withdrawn_at = $2,
		       revision = revision + 1, updated_at = $2
		 WHERE id = $1 AND state = 'published'
	`, id, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Distinguish: does the row exist at all?
		var exists bool
		_ = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM advisories WHERE id = $1)`, id).Scan(&exists)
		if !exists {
			return ErrNotFound
		}
		return ErrConflict
	}
	return nil
}

func (s *AdvisoryStore) MarkCitadelEmitted(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE advisories SET citadel_emitted = true WHERE id = $1`, id)
	return err
}

type AdvisoryFilter struct {
	State  string
	TLP    string
	Limit  int
	Offset int
}

func (s *AdvisoryStore) List(ctx context.Context, f AdvisoryFilter) ([]*Advisory, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, incident_id, csaf_id, csaf_version, csaf_doc, state, tlp,
		       title, summary, revision, published_at, withdrawn_at,
		       published_by, citadel_emitted, created_at, updated_at
		  FROM advisories
		 WHERE ($1 = '' OR state = $1)
		   AND ($2 = '' OR tlp = $2)
	     ORDER BY created_at DESC, id DESC
	     LIMIT $3 OFFSET $4
	`, f.State, f.TLP, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := make([]*Advisory, 0, f.Limit)
	for rows.Next() {
		a := &Advisory{}
		var doc []byte
		if err := rows.Scan(&a.ID, &a.IncidentID, &a.CSAFID, &a.CSAFVersion, &doc,
			&a.State, &a.TLP, &a.Title, &a.Summary,
			&a.Revision, &a.PublishedAt, &a.WithdrawnAt,
			&a.PublishedBy, &a.CitadelEmitted,
			&a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, 0, err
		}
		if len(doc) > 0 {
			if err := json.Unmarshal(doc, &a.CSAFDoc); err != nil {
				return nil, 0, fmt.Errorf("unmarshal csaf_doc: %w", err)
			}
		}
		out = append(out, a)
	}
	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM advisories
		 WHERE ($1 = '' OR state = $1) AND ($2 = '' OR tlp = $2)
	`, f.State, f.TLP).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count query: %w", err)
	}
	return out, total, rows.Err()
}

func (s *AdvisoryStore) CountByState(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT state, COUNT(*) FROM advisories GROUP BY state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}
