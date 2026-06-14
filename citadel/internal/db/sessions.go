package db

import (
	"context"
	"fmt"
	"time"
)

// SessionExists returns the role and role_group for a valid, non-expired,
// non-revoked session for the given user_id.
// Returns ("", "", false, nil) if no valid session exists.
func (d *DB) SessionExists(ctx context.Context, userID int64) (role, roleGroup string, exists bool, err error) {
	row := d.Pool.QueryRow(ctx,
		`SELECT role, role_group FROM sessions
		 WHERE user_id = $1
		   AND revoked = false
		   AND expires_at > now()
		 ORDER BY created_at DESC
		 LIMIT 1`,
		userID,
	)
	err = row.Scan(&role, &roleGroup)
	if err != nil {
		// pgx returns pgx.ErrNoRows when no row found
		return "", "", false, nil
	}
	return role, roleGroup, true, nil
}

// ActionCount returns how many WORM entries the given user_id produced
// in the last windowDur. Used by AUGUR rule_02.
func (d *DB) ActionCount(ctx context.Context, userID int64, windowDur time.Duration) (int, error) {
	since := time.Now().UTC().Add(-windowDur)
	var count int
	err := d.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM marshal_decisions
		 WHERE (kerkese->'actor'->>'user_id')::bigint = $1
		   AND created_at >= $2`,
		userID, since,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("db: action count: %w", err)
	}
	return count, nil
}
