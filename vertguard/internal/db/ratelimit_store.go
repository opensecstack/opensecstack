package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/vertguard/internal/ratelimit"
)

// RateLimitOverrideStore is the pgx-backed implementation of
// ratelimit.OverrideStore. Mirrors db.AuditStore composition.
type RateLimitOverrideStore struct {
	pool *pgxpool.Pool
}

// NewRateLimitOverrideStore wires a pool into the ratelimit package
// without forcing ratelimit to import pgx transitively.
func NewRateLimitOverrideStore(d *DB) *RateLimitOverrideStore {
	if d == nil {
		return nil
	}
	return &RateLimitOverrideStore{pool: d.Pool}
}

// List returns active overrides — expired rows are filtered server-side
// so a stuck refresher can't keep an expired override alive.
func (s *RateLimitOverrideStore) List(ctx context.Context) ([]ratelimit.Override, error) {
	if s == nil || s.pool == nil {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT kind, value, rps, burst,
		       COALESCE(reason,''), COALESCE(created_by,''),
		       created_at, expires_at
		  FROM rate_limit_overrides
		 WHERE expires_at IS NULL OR expires_at > NOW()
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list rate_limit_overrides: %w", err)
	}
	defer rows.Close()

	out := make([]ratelimit.Override, 0)
	for rows.Next() {
		var o ratelimit.Override
		var exp *time.Time
		if err := rows.Scan(
			&o.Kind, &o.Value, &o.RPS, &o.Burst,
			&o.Reason, &o.CreatedBy, &o.CreatedAt, &exp,
		); err != nil {
			return nil, fmt.Errorf("scan rate_limit_override: %w", err)
		}
		o.ExpiresAt = exp
		out = append(out, o)
	}
	return out, rows.Err()
}

// Add upserts on (kind, value) — re-issuing an override with the same
// key replaces the row so operators can rotate quotas without DELETE.
func (s *RateLimitOverrideStore) Add(ctx context.Context, o ratelimit.Override) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("rate_limit_overrides: nil store")
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO rate_limit_overrides
		    (id, kind, value, rps, burst, reason, created_by, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (kind, value) DO UPDATE
		   SET rps        = EXCLUDED.rps,
		       burst      = EXCLUDED.burst,
		       reason     = EXCLUDED.reason,
		       created_by = EXCLUDED.created_by,
		       created_at = EXCLUDED.created_at,
		       expires_at = EXCLUDED.expires_at`,
		uuid.New(), o.Kind, o.Value, o.RPS, o.Burst,
		nullIfEmpty(o.Reason), nullIfEmpty(o.CreatedBy),
		o.CreatedAt, o.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert rate_limit_override: %w", err)
	}
	return nil
}

// Remove deletes by (kind, value). Idempotent.
func (s *RateLimitOverrideStore) Remove(ctx context.Context, kind, value string) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("rate_limit_overrides: nil store")
	}
	_, err := s.pool.Exec(ctx,
		`DELETE FROM rate_limit_overrides WHERE kind = $1 AND value = $2`,
		kind, value)
	if err != nil {
		return fmt.Errorf("delete rate_limit_override: %w", err)
	}
	return nil
}
