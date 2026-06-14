package store

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

// Sighting is a row in the sightings table. A sighting records that an
// external platform (APIGuard, IRFlow, NIS2 Compass, or manual) observed a
// known IOC against a specific resource.
type Sighting struct {
	ID           uuid.UUID       `json:"id"`
	IOCID        uuid.UUID       `json:"ioc_id"`
	Platform     string          `json:"platform"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	ObservedAt   time.Time       `json:"observed_at"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

// SightingStore persists sightings rows.
type SightingStore struct {
	pool *pgxpool.Pool
}

// NewSightingStore binds a store to the pool.
func NewSightingStore(pool *pgxpool.Pool) *SightingStore {
	return &SightingStore{pool: pool}
}

// Create inserts a new sighting.
func (s *SightingStore) Create(ctx context.Context, sight *Sighting) error {
	if len(sight.Metadata) == 0 {
		sight.Metadata = json.RawMessage(`{}`)
	}
	if sight.ObservedAt.IsZero() {
		sight.ObservedAt = time.Now().UTC()
	}
	const q = `
INSERT INTO sightings (ioc_id, platform, resource_type, resource_id, observed_at, metadata)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
RETURNING id, created_at`
	return s.pool.QueryRow(ctx, q,
		sight.IOCID, sight.Platform, sight.ResourceType, sight.ResourceID,
		sight.ObservedAt, sight.Metadata,
	).Scan(&sight.ID, &sight.CreatedAt)
}

// ForIOC returns every sighting attached to an IOC, newest first.
func (s *SightingStore) ForIOC(ctx context.Context, iocID uuid.UUID, limit int) ([]*Sighting, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	const q = `
SELECT id, ioc_id, platform, resource_type, resource_id, observed_at, metadata::text, created_at
FROM sightings WHERE ioc_id = $1 ORDER BY observed_at DESC LIMIT $2`
	rows, err := s.pool.Query(ctx, q, iocID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Sighting
	for rows.Next() {
		var (
			sight Sighting
			meta  string
		)
		if err := rows.Scan(
			&sight.ID, &sight.IOCID, &sight.Platform, &sight.ResourceType, &sight.ResourceID,
			&sight.ObservedAt, &meta, &sight.CreatedAt,
		); err != nil {
			return nil, err
		}
		sight.Metadata = json.RawMessage(meta)
		out = append(out, &sight)
	}
	return out, rows.Err()
}

// CountByPlatform returns the count of sightings grouped by platform.
func (s *SightingStore) CountByPlatform(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT platform, count(*)::int FROM sightings GROUP BY platform`)
	if err != nil {
		return nil, fmt.Errorf("count: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var p string
		var c int
		if err := rows.Scan(&p, &c); err != nil {
			return nil, err
		}
		out[p] = c
	}
	return out, rows.Err()
}

// IOCByValue fetches an IOC by (type, value) — the common lookup path for
// ecosystem clients that discover a suspicious indicator and want to know if
// ThreatFlow has any intel on it.
func (s *IOCStore) IOCByValue(ctx context.Context, iocType, value string) (*IOC, error) {
	const q = `
SELECT id, stix_id, type, value, pattern, pattern_hash, feed_id,
       coalesce(source, ''), confidence, coalesce(description, ''),
       tags, first_seen, last_seen, expires_at, revoked, coalesce(cve, ''),
       created_at, updated_at
FROM iocs WHERE type = $1 AND value = $2 AND revoked = FALSE LIMIT 1`
	row := s.pool.QueryRow(ctx, q, iocType, value)
	ioc, err := scanIOC(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return ioc, nil
}
