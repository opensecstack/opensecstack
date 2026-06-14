package db

// Migration: apply the following DDL before using these functions.
//
// -- CREATE TABLE IF NOT EXISTS revoked_refresh_tokens (
// --   token_hash TEXT PRIMARY KEY,
// --   revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
// -- );

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RevokedToken is a display-safe representation of a revoked refresh token.
// token_hash is truncated to the first 8 characters so the full hash is never
// exposed in API responses.
type RevokedToken struct {
	TokenHashPrefix string    `json:"token_hash"`
	RevokedAt       time.Time `json:"revoked_at"`
}

// RevokeRefreshToken inserts a refresh token hash into the revoked_refresh_tokens
// table. If the token has already been revoked (duplicate key) the call is a no-op.
func RevokeRefreshToken(ctx context.Context, pool *pgxpool.Pool, tokenHash string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO revoked_refresh_tokens (token_hash)
		VALUES ($1)
		ON CONFLICT (token_hash) DO NOTHING
	`, tokenHash)
	if err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}

// IsRefreshTokenRevoked reports whether the given token hash exists in the
// revoked_refresh_tokens table.
func IsRefreshTokenRevoked(ctx context.Context, pool *pgxpool.Pool, tokenHash string) (bool, error) {
	var exists bool
	err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM revoked_refresh_tokens WHERE token_hash = $1
		)
	`, tokenHash).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("checking refresh token revocation: %w", err)
	}
	return exists, nil
}

// ListRevokedRefreshTokens returns up to limit revoked tokens, ordered by
// revoked_at DESC, with token_hash truncated to the first 8 characters for
// display safety.
func ListRevokedRefreshTokens(ctx context.Context, pool *pgxpool.Pool, limit, offset int) ([]RevokedToken, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := pool.Query(ctx, `
		SELECT token_hash, revoked_at
		FROM revoked_refresh_tokens
		ORDER BY revoked_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("querying revoked refresh tokens: %w", err)
	}
	defer rows.Close()

	var tokens []RevokedToken
	for rows.Next() {
		var fullHash string
		var revokedAt time.Time
		if err := rows.Scan(&fullHash, &revokedAt); err != nil {
			return nil, fmt.Errorf("scanning revoked refresh token row: %w", err)
		}
		prefix := fullHash
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		tokens = append(tokens, RevokedToken{
			TokenHashPrefix: prefix,
			RevokedAt:       revokedAt,
		})
	}
	if tokens == nil {
		tokens = []RevokedToken{}
	}
	return tokens, rows.Err()
}
