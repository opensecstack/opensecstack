package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/opensecstack/vertguard/internal/auth/denylist"
)

// SaveDenylistEntry inserts (or updates on conflict) a token denylist
// row. Auto-fills id + revoked_at when zero — caller-supplied values
// win, so admin imports remain replayable.
func (d *DB) SaveDenylistEntry(ctx context.Context, e *denylist.Entry) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.RevokedAt.IsZero() {
		e.RevokedAt = time.Now().UTC()
	}
	var expiresAt any
	if e.ExpiresAt != nil {
		expiresAt = *e.ExpiresAt
	}
	_, err := d.Pool.Exec(ctx, `
		INSERT INTO token_denylist (
			id, kind, value, reason, revoked_by, revoked_at, expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (kind, value) DO UPDATE SET
			reason     = EXCLUDED.reason,
			revoked_by = EXCLUDED.revoked_by,
			revoked_at = EXCLUDED.revoked_at,
			expires_at = EXCLUDED.expires_at`,
		e.ID, e.Kind, e.Value,
		nullIfEmpty(e.Reason), nullIfEmpty(e.RevokedBy),
		e.RevokedAt, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("insert denylist entry: %w", err)
	}
	return nil
}

// RemoveDenylistEntry deletes by (kind, value). Idempotent.
func (d *DB) RemoveDenylistEntry(ctx context.Context, kind, value string) error {
	_, err := d.Pool.Exec(ctx,
		`DELETE FROM token_denylist WHERE kind=$1 AND value=$2`,
		kind, value,
	)
	if err != nil {
		return fmt.Errorf("delete denylist entry: %w", err)
	}
	return nil
}

// ListDenylistEntries returns active entries (expired rows filtered out
// in SQL so the cache loop stays cheap).
func (d *DB) ListDenylistEntries(ctx context.Context) ([]denylist.Entry, error) {
	rows, err := d.Pool.Query(ctx, `
		SELECT id, kind, value,
		       COALESCE(reason,''), COALESCE(revoked_by,''),
		       revoked_at, expires_at
		FROM token_denylist
		WHERE expires_at IS NULL OR expires_at > NOW()
		ORDER BY revoked_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list denylist: %w", err)
	}
	defer rows.Close()

	out := make([]denylist.Entry, 0, 32)
	for rows.Next() {
		var e denylist.Entry
		var exp *time.Time
		if err := rows.Scan(
			&e.ID, &e.Kind, &e.Value,
			&e.Reason, &e.RevokedBy,
			&e.RevokedAt, &exp,
		); err != nil {
			return nil, fmt.Errorf("scan denylist row: %w", err)
		}
		e.ExpiresAt = exp
		out = append(out, e)
	}
	return out, rows.Err()
}

// DenylistStore adapts a *DB to the denylist.Store interface without
// polluting the DB type's method namespace with generic List/Add/Remove
// names. Use NewDenylistStore(db) at wire-up.
type DenylistStore struct{ d *DB }

// NewDenylistStore builds a denylist.Store backed by the given DB.
func NewDenylistStore(d *DB) *DenylistStore { return &DenylistStore{d: d} }

// List satisfies denylist.Store.
func (s *DenylistStore) List(ctx context.Context) ([]denylist.Entry, error) {
	return s.d.ListDenylistEntries(ctx)
}

// Add satisfies denylist.Store.
func (s *DenylistStore) Add(ctx context.Context, e denylist.Entry) error {
	return s.d.SaveDenylistEntry(ctx, &e)
}

// Remove satisfies denylist.Store.
func (s *DenylistStore) Remove(ctx context.Context, kind, value string) error {
	return s.d.RemoveDenylistEntry(ctx, kind, value)
}
