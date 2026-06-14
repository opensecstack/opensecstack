// Package db — session_store manages the `sessions` table.
// Implements auth.SessionStore backed by PostgreSQL (replaces the in-memory
// MemorySessionStore from v0.0.1 when a DB connection is available).
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/cyberpath/internal/auth"
)

// DBSessionStore implements auth.SessionStore backed by the `sessions` table.
type DBSessionStore struct {
	Pool *pgxpool.Pool
}

// NewDBSessionStore wires a DBSessionStore.
func NewDBSessionStore(pool *pgxpool.Pool) *DBSessionStore {
	return &DBSessionStore{Pool: pool}
}

// Create persists a new session row. Returns an error if ID or
// RefreshTokenHash is empty, or if the insert fails (e.g. duplicate hash).
func (s *DBSessionStore) Create(sess auth.Session) error {
	const op = "db/session_store/Create"
	if sess.ID == "" {
		return fmt.Errorf("%s: session id empty", op)
	}
	if sess.RefreshTokenHash == "" {
		return fmt.Errorf("%s: refresh token hash empty", op)
	}
	_, err := s.Pool.Exec(context.Background(), `
		INSERT INTO sessions
			(id, user_id, refresh_token_hash, issued_at, expires_at, revoked_at, ip_address, user_agent)
		VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8)`,
		sess.ID, sess.UserID, sess.RefreshTokenHash,
		sess.IssuedAt, sess.ExpiresAt,
		nullableTime(sess.RevokedAt),
		nullableString(sess.IPAddress),
		nullableString(sess.UserAgent),
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// GetByRefreshToken hashes the wire token and looks up the matching session.
// Returns auth.ErrSessionNotFound when no row matches.
func (s *DBSessionStore) GetByRefreshToken(refreshToken string) (*auth.Session, error) {
	const op = "db/session_store/GetByRefreshToken"
	hash := auth.HashRefreshToken(refreshToken)
	row := s.Pool.QueryRow(context.Background(), `
		SELECT id, user_id::text, refresh_token_hash,
		       issued_at, expires_at, revoked_at, ip_address, user_agent
		FROM sessions
		WHERE refresh_token_hash = $1`, hash)
	return scanSession(op, row)
}

// Revoke sets revoked_at = now() for the session. Idempotent: revoking an
// already-revoked or unknown session returns nil.
func (s *DBSessionStore) Revoke(sessionID string) error {
	const op = "db/session_store/Revoke"
	_, err := s.Pool.Exec(context.Background(), `
		UPDATE sessions SET revoked_at = now()
		WHERE id = $1 AND revoked_at IS NULL`, sessionID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// RevokeAll revokes every active session for the user. Idempotent.
func (s *DBSessionStore) RevokeAll(userID string) error {
	const op = "db/session_store/RevokeAll"
	_, err := s.Pool.Exec(context.Background(), `
		UPDATE sessions SET revoked_at = now()
		WHERE user_id = $1::uuid AND revoked_at IS NULL`, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// Validate returns the session iff it is currently active (not expired,
// not revoked). Returns auth.ErrSessionNotFound otherwise.
func (s *DBSessionStore) Validate(refreshToken string) (*auth.Session, error) {
	sess, err := s.GetByRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}
	if !sess.Active(time.Now()) {
		return nil, auth.ErrSessionNotFound
	}
	return sess, nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

func scanSession(op string, row pgx.Row) (*auth.Session, error) {
	var sess auth.Session
	var ip, ua *string
	if err := row.Scan(
		&sess.ID, &sess.UserID, &sess.RefreshTokenHash,
		&sess.IssuedAt, &sess.ExpiresAt, &sess.RevokedAt,
		&ip, &ua,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrSessionNotFound
		}
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if ip != nil {
		sess.IPAddress = *ip
	}
	if ua != nil {
		sess.UserAgent = *ua
	}
	return &sess, nil
}
