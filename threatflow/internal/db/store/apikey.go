package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// APIKey mirrors a row in api_keys. The plaintext key is never stored.
type APIKey struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	KeyHash    string     `json:"-"`
	Role       string     `json:"role"`
	Enabled    bool       `json:"enabled"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// HashAPIKey returns the canonical hex-encoded SHA-256 of a plaintext key.
// Used both at creation time and on validation so comparison can be
// constant-time on the hash column.
func HashAPIKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// APIKeyStore persists api_keys rows.
type APIKeyStore struct {
	pool *pgxpool.Pool
}

// NewAPIKeyStore binds a store to the pool.
func NewAPIKeyStore(pool *pgxpool.Pool) *APIKeyStore {
	return &APIKeyStore{pool: pool}
}

// Create inserts a new API key row. key.KeyHash must already be populated.
func (s *APIKeyStore) Create(ctx context.Context, key *APIKey) error {
	const q = `
INSERT INTO api_keys (name, key_hash, role, enabled, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, created_at, updated_at`
	return s.pool.QueryRow(ctx, q,
		key.Name, key.KeyHash, key.Role, key.Enabled, key.ExpiresAt,
	).Scan(&key.ID, &key.CreatedAt, &key.UpdatedAt)
}

// FindByHash fetches an API key by its stored SHA-256 hash. Returns the row
// when it exists, is enabled, and (if expires_at is set) not expired.
func (s *APIKeyStore) FindByHash(ctx context.Context, hash string) (*APIKey, error) {
	const q = `
SELECT id, name, key_hash, role, enabled, expires_at, last_used_at, created_at, updated_at
FROM api_keys
WHERE key_hash = $1
  AND enabled = TRUE
  AND (expires_at IS NULL OR expires_at > now())`
	var k APIKey
	err := s.pool.QueryRow(ctx, q, hash).Scan(
		&k.ID, &k.Name, &k.KeyHash, &k.Role, &k.Enabled,
		&k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt, &k.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &k, err
}

// List returns every API key row (plaintext is never available, only hashes).
func (s *APIKeyStore) List(ctx context.Context) ([]*APIKey, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id, name, key_hash, role, enabled, expires_at, last_used_at, created_at, updated_at
FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(
			&k.ID, &k.Name, &k.KeyHash, &k.Role, &k.Enabled,
			&k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt, &k.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

// TouchUsed updates last_used_at on the key — best-effort, errors ignored.
func (s *APIKeyStore) TouchUsed(ctx context.Context, id uuid.UUID) {
	_, _ = s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)
}

// Revoke disables an API key.
func (s *APIKeyStore) Revoke(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE api_keys SET enabled = FALSE, updated_at = now() WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes an API key permanently.
func (s *APIKeyStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM api_keys WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
