package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TTPTag mirrors a row in ttp_tags.
type TTPTag struct {
	IOCID       uuid.UUID `json:"ioc_id"`
	TechniqueID string    `json:"technique_id"`
	Source      string    `json:"source"`
	Confidence  int       `json:"confidence"`
	CreatedAt   time.Time `json:"created_at"`
}

// TechniqueCount pairs a technique ID with how many IOCs reference it.
type TechniqueCount struct {
	TechniqueID string `json:"technique_id"`
	Count       int    `json:"count"`
}

// TTPStore persists ttp_tags rows.
type TTPStore struct {
	pool *pgxpool.Pool
}

// NewTTPStore binds a store to the pool.
func NewTTPStore(pool *pgxpool.Pool) *TTPStore {
	return &TTPStore{pool: pool}
}

// Upsert inserts or updates a tag. A re-tag with a higher confidence or a
// `feed` source overrides the existing row.
func (s *TTPStore) Upsert(ctx context.Context, tag *TTPTag) error {
	const q = `
INSERT INTO ttp_tags (ioc_id, technique_id, source, confidence)
VALUES ($1, $2, $3, $4)
ON CONFLICT (ioc_id, technique_id) DO UPDATE SET
    confidence = GREATEST(ttp_tags.confidence, EXCLUDED.confidence),
    source     = CASE
        WHEN EXCLUDED.source = 'manual' THEN 'manual'
        WHEN EXCLUDED.source = 'feed'   THEN 'feed'
        ELSE ttp_tags.source
    END
RETURNING created_at`
	return s.pool.QueryRow(ctx, q, tag.IOCID, tag.TechniqueID, tag.Source, tag.Confidence).
		Scan(&tag.CreatedAt)
}

// UpsertMany runs Upsert in a single transaction.
func (s *TTPStore) UpsertMany(ctx context.Context, tags []*TTPTag) error {
	if len(tags) == 0 {
		return nil
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, t := range tags {
		_, err := tx.Exec(ctx, `
INSERT INTO ttp_tags (ioc_id, technique_id, source, confidence)
VALUES ($1, $2, $3, $4)
ON CONFLICT (ioc_id, technique_id) DO UPDATE SET
    confidence = GREATEST(ttp_tags.confidence, EXCLUDED.confidence),
    source     = CASE
        WHEN EXCLUDED.source = 'manual' THEN 'manual'
        WHEN EXCLUDED.source = 'feed'   THEN 'feed'
        ELSE ttp_tags.source
    END`, t.IOCID, t.TechniqueID, t.Source, t.Confidence)
		if err != nil {
			return fmt.Errorf("upsert ttp %s→%s: %w", t.IOCID, t.TechniqueID, err)
		}
	}
	return tx.Commit(ctx)
}

// ForIOC returns all tags for a single IOC.
func (s *TTPStore) ForIOC(ctx context.Context, iocID uuid.UUID) ([]*TTPTag, error) {
	const q = `
SELECT ioc_id, technique_id, source, confidence, created_at
FROM ttp_tags WHERE ioc_id = $1 ORDER BY confidence DESC, technique_id`
	rows, err := s.pool.Query(ctx, q, iocID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*TTPTag
	for rows.Next() {
		var t TTPTag
		if err := rows.Scan(&t.IOCID, &t.TechniqueID, &t.Source, &t.Confidence, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// Summary returns technique → count of IOCs tagged with it.
func (s *TTPStore) Summary(ctx context.Context, limit int) ([]TechniqueCount, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	const q = `
SELECT technique_id, count(*)::int
FROM ttp_tags
GROUP BY technique_id
ORDER BY count(*) DESC, technique_id
LIMIT $1`
	rows, err := s.pool.Query(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TechniqueCount
	for rows.Next() {
		var tc TechniqueCount
		if err := rows.Scan(&tc.TechniqueID, &tc.Count); err != nil {
			return nil, err
		}
		out = append(out, tc)
	}
	return out, rows.Err()
}
