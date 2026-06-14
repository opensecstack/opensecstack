package token

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store handles refresh token persistence.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new Store backed by the given connection pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// hashToken returns the SHA-256 hex digest of a raw token string.
func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// SaveRefreshToken inserts a refresh token row into the database.
// The raw token is hashed before storage — the plaintext is never persisted.
func (s *Store) SaveRefreshToken(ctx context.Context, raw, clientID, userID string, scopes []string, expiresAt time.Time) error {
	const q = `
		INSERT INTO refresh_tokens (token_hash, client_id, user_id, scopes, expires_at, revoked)
		VALUES ($1, $2, $3, $4, $5, false)`

	_, err := s.pool.Exec(ctx, q,
		hashToken(raw),
		clientID,
		userID,
		scopes,
		expiresAt,
	)
	return err
}

// ConsumeRefreshToken atomically looks up and deletes a refresh token,
// returning its associated metadata. Returns an error if the token is not
// found, has expired, or has been revoked.
func (s *Store) ConsumeRefreshToken(ctx context.Context, raw string) (clientID, userID string, scopes []string, err error) {
	const q = `
		DELETE FROM refresh_tokens
		WHERE token_hash = $1
		  AND revoked    = false
		  AND expires_at > now()
		RETURNING client_id, user_id, scopes`

	row := s.pool.QueryRow(ctx, q, hashToken(raw))
	if err = row.Scan(&clientID, &userID, &scopes); err != nil {
		return "", "", nil, errors.New("token: refresh token not found, expired, or revoked")
	}
	return clientID, userID, scopes, nil
}

// RevokeRefreshToken marks a refresh token as revoked by its hash.
func (s *Store) RevokeRefreshToken(ctx context.Context, raw string) error {
	const q = `UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1`
	_, err := s.pool.Exec(ctx, q, hashToken(raw))
	return err
}
