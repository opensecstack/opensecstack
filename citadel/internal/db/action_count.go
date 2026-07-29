package db

import (
	"context"
	"fmt"
	"time"
)

// ActionCount returns how many WORM entries the given user_id (sinauth UUID)
// produced in the last windowDur. Used by AUGUR rule_02.
func (d *DB) ActionCount(ctx context.Context, userID string, windowDur time.Duration) (int, error) {
	since := time.Now().UTC().Add(-windowDur)
	var count int
	err := d.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM marshal_decisions
		 WHERE kerkese->'actor'->>'user_id' = $1
		   AND created_at >= $2`,
		userID, since,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("db: action count: %w", err)
	}
	return count, nil
}
