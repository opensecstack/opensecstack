package handlers

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// resolveUserID looks up the UUID for the given username.
// Returns an empty string if the user does not exist or the query fails,
// which preserves the same silent-failure behaviour found across the handlers.
func resolveUserID(ctx context.Context, pool *pgxpool.Pool, username string) string {
	var id string
	pool.QueryRow(ctx, `SELECT id FROM users WHERE username=$1`, username).Scan(&id)
	return id
}
