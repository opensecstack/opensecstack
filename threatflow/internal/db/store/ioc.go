package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a lookup has no matching row.
var ErrNotFound = errors.New("not found")

// IOCStore persists iocs rows.
type IOCStore struct {
	pool *pgxpool.Pool
}

// NewIOCStore returns a store bound to the given pool.
func NewIOCStore(pool *pgxpool.Pool) *IOCStore {
	return &IOCStore{pool: pool}
}

// HashPattern returns the SHA-256 hash of a normalised STIX pattern. The pattern
// is lowercased and whitespace-collapsed so equivalent patterns dedupe.
func HashPattern(pattern string) string {
	normalised := strings.Join(strings.Fields(strings.ToLower(pattern)), " ")
	sum := sha256.Sum256([]byte(normalised))
	return hex.EncodeToString(sum[:])
}

// Upsert inserts a new IOC or updates last_seen + confidence on conflict.
// Deduplication key is pattern_hash.
func (s *IOCStore) Upsert(ctx context.Context, ioc *IOC) error {
	if ioc.PatternHash == "" {
		ioc.PatternHash = HashPattern(ioc.Pattern)
	}
	if ioc.Tags == nil {
		ioc.Tags = []string{}
	}
	now := time.Now().UTC()
	if ioc.FirstSeen.IsZero() {
		ioc.FirstSeen = now
	}
	if ioc.LastSeen.IsZero() {
		ioc.LastSeen = now
	}

	const q = `
INSERT INTO iocs (
    stix_id, type, value, pattern, pattern_hash, feed_id, source,
    confidence, description, tags, first_seen, last_seen, expires_at, revoked, cve
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
ON CONFLICT (pattern_hash) DO UPDATE SET
    last_seen  = GREATEST(iocs.last_seen, EXCLUDED.last_seen),
    confidence = GREATEST(iocs.confidence, EXCLUDED.confidence),
    tags       = ARRAY(SELECT DISTINCT unnest(iocs.tags || EXCLUDED.tags)),
    updated_at = now()
RETURNING id, first_seen, last_seen, created_at, updated_at`

	row := s.pool.QueryRow(ctx, q,
		ioc.StixID, ioc.Type, ioc.Value, ioc.Pattern, ioc.PatternHash,
		ioc.FeedID, nullIfEmpty(ioc.Source),
		ioc.Confidence, nullIfEmpty(ioc.Description), ioc.Tags,
		ioc.FirstSeen, ioc.LastSeen, ioc.ExpiresAt, ioc.Revoked, nullIfEmpty(ioc.CVE),
	)
	if err := row.Scan(&ioc.ID, &ioc.FirstSeen, &ioc.LastSeen, &ioc.CreatedAt, &ioc.UpdatedAt); err != nil {
		return fmt.Errorf("upsert ioc: %w", err)
	}
	return nil
}

// Get fetches an IOC by ID.
func (s *IOCStore) Get(ctx context.Context, id uuid.UUID) (*IOC, error) {
	const q = `
SELECT id, stix_id, type, value, pattern, pattern_hash, feed_id,
       coalesce(source, ''), confidence, coalesce(description, ''),
       tags, first_seen, last_seen, expires_at, revoked, coalesce(cve, ''),
       created_at, updated_at
FROM iocs WHERE id = $1`
	row := s.pool.QueryRow(ctx, q, id)
	ioc, err := scanIOC(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return ioc, nil
}

// List returns IOCs matching the filter, ordered by last_seen DESC.
func (s *IOCStore) List(ctx context.Context, f IOCFilter) ([]*IOC, int, error) {
	var (
		where []string
		args  []any
	)
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.Type != "" {
		add("type = $%d", f.Type)
	}
	if f.Value != "" {
		add("value = $%d", f.Value)
	}
	if f.FeedID != nil {
		add("feed_id = $%d", *f.FeedID)
	}
	if f.Tag != "" {
		add("$%d = ANY(tags)", f.Tag)
	}
	if f.MinConf > 0 {
		add("confidence >= $%d", f.MinConf)
	}
	if f.Revoked != nil {
		add("revoked = $%d", *f.Revoked)
	}
	if f.Search != "" {
		add("to_tsvector('english', coalesce(description, '') || ' ' || value) @@ plainto_tsquery('english', $%d)", f.Search)
	}
	clause := ""
	if len(where) > 0 {
		clause = "WHERE " + strings.Join(where, " AND ")
	}

	var total int
	countQ := "SELECT count(*) FROM iocs " + clause
	if err := s.pool.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	args = append(args, limit, f.Offset)

	listQ := fmt.Sprintf(`
SELECT id, stix_id, type, value, pattern, pattern_hash, feed_id,
       coalesce(source, ''), confidence, coalesce(description, ''),
       tags, first_seen, last_seen, expires_at, revoked, coalesce(cve, ''),
       created_at, updated_at
FROM iocs %s
ORDER BY last_seen DESC
LIMIT $%d OFFSET $%d`, clause, len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, listQ, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var out []*IOC
	for rows.Next() {
		ioc, err := scanIOC(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ioc)
	}
	return out, total, rows.Err()
}

// Revoke marks an IOC as revoked (soft delete).
func (s *IOCStore) Revoke(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE iocs SET revoked = TRUE, updated_at = now() WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete permanently removes an IOC.
func (s *IOCStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM iocs WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanIOC(r rowScanner) (*IOC, error) {
	var ioc IOC
	if err := r.Scan(
		&ioc.ID, &ioc.StixID, &ioc.Type, &ioc.Value, &ioc.Pattern, &ioc.PatternHash,
		&ioc.FeedID, &ioc.Source, &ioc.Confidence, &ioc.Description,
		&ioc.Tags, &ioc.FirstSeen, &ioc.LastSeen, &ioc.ExpiresAt, &ioc.Revoked, &ioc.CVE,
		&ioc.CreatedAt, &ioc.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &ioc, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
