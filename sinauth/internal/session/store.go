package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) Create(ctx context.Context, userID, username string, ttl time.Duration) (*Session, error) {
	b := make([]byte, 32)
	rand.Read(b)
	id := hex.EncodeToString(b)
	expiresAt := time.Now().Add(ttl)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sso_sessions (id, user_id, username, expires_at) VALUES ($1,$2,$3,$4)`,
		id, userID, username, expiresAt)
	if err != nil {
		return nil, err
	}
	return &Session{ID: id, UserID: userID, Username: username, ExpiresAt: expiresAt}, nil
}

func (s *Store) Get(ctx context.Context, id string) (*Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx,
		`SELECT id, user_id, username, created_at, expires_at
         FROM sso_sessions WHERE id=$1 AND expires_at > now()`, id,
	).Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sso_sessions WHERE id=$1`, id)
	return err
}

func (s *Store) ListAll(ctx context.Context) ([]Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, username, created_at, expires_at
		 FROM sso_sessions WHERE expires_at > now() ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

func (s *Store) ListByUsername(ctx context.Context, username string) ([]Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, username, created_at, expires_at
		 FROM sso_sessions WHERE username=$1 AND expires_at > now() ORDER BY created_at DESC`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var sess Session
		if err := rows.Scan(&sess.ID, &sess.UserID, &sess.Username, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}
