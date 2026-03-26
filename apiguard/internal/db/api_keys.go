package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// APIKey represents a row in the api_keys table.
// key_hash is never exposed in JSON responses.
type APIKey struct {
	ID          uuid.UUID      `json:"id"`
	Label       sql.NullString `json:"label"`
	CreatedBy   string         `json:"created_by"`
	IsActive    bool           `json:"is_active"`
	LastUsedAt  sql.NullTime   `json:"last_used_at"`
	CreatedAt   time.Time      `json:"created_at"`
	RevokedAt   sql.NullTime   `json:"revoked_at"`
	RevokedBy   sql.NullString `json:"revoked_by"`
}

// CreateAPIKey generates a new API key, stores its SHA-256 hash, and returns
// the inserted APIKey row together with the plaintext key (shown only once).
func (d *DB) CreateAPIKey(ctx context.Context, label, createdBy string) (*APIKey, string, error) {
	// Generate 32 cryptographically random bytes and encode as hex (64-char string).
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("generating api key bytes: %w", err)
	}
	plaintext := hex.EncodeToString(raw)

	// SHA-256 hash of the plaintext key for storage.
	sum := sha256.Sum256([]byte(plaintext))
	keyHash := hex.EncodeToString(sum[:])

	var lbl sql.NullString
	if label != "" {
		lbl = sql.NullString{String: label, Valid: true}
	}

	key := &APIKey{}
	err := d.Pool.QueryRow(ctx, `
		INSERT INTO api_keys (key_hash, label, created_by)
		VALUES ($1, $2, $3)
		RETURNING id, label, created_by, is_active, last_used_at, created_at, revoked_at, revoked_by
	`, keyHash, lbl, createdBy).Scan(
		&key.ID,
		&key.Label,
		&key.CreatedBy,
		&key.IsActive,
		&key.LastUsedAt,
		&key.CreatedAt,
		&key.RevokedAt,
		&key.RevokedBy,
	)
	if err != nil {
		return nil, "", fmt.Errorf("inserting api key: %w", err)
	}

	return key, plaintext, nil
}

// ListAPIKeysPaginated returns active API keys with pagination. key_hash is never included.
// Returns the page of keys, the total count of active keys, and any error.
func (d *DB) ListAPIKeysPaginated(ctx context.Context, limit, offset int) ([]APIKey, int, error) {
	var total int
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_keys WHERE is_active = TRUE`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting api keys: %w", err)
	}

	rows, err := d.Pool.Query(ctx, `
		SELECT id, label, created_by, is_active, last_used_at, created_at, revoked_at, revoked_by
		FROM api_keys
		WHERE is_active = TRUE
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying api keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(
			&k.ID,
			&k.Label,
			&k.CreatedBy,
			&k.IsActive,
			&k.LastUsedAt,
			&k.CreatedAt,
			&k.RevokedAt,
			&k.RevokedBy,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning api key row: %w", err)
		}
		keys = append(keys, k)
	}
	if keys == nil {
		keys = []APIKey{}
	}
	return keys, total, rows.Err()
}

// RevokeAPIKey marks an API key as inactive and records who revoked it.
func (d *DB) RevokeAPIKey(ctx context.Context, id uuid.UUID, revokedBy string) error {
	tag, err := d.Pool.Exec(ctx, `
		UPDATE api_keys
		SET is_active = FALSE,
		    revoked_at = NOW(),
		    revoked_by = $1
		WHERE id = $2 AND is_active = TRUE
	`, revokedBy, id)
	if err != nil {
		return fmt.Errorf("revoking api key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("api key not found or already revoked")
	}
	return nil
}

// LookupAPIKeyByHash checks whether a SHA-256 hex hash matches an active key
// and, if so, records last_used_at. Returns (found, error).
func (d *DB) LookupAPIKeyByHash(ctx context.Context, keyHash string) (bool, error) {
	var id uuid.UUID
	err := d.Pool.QueryRow(ctx, `
		SELECT id FROM api_keys
		WHERE key_hash = $1 AND is_active = TRUE
		LIMIT 1
	`, keyHash).Scan(&id)
	if err != nil {
		// pgx returns pgx.ErrNoRows when no row is found.
		return false, nil
	}

	// Update last_used_at in the background — best effort, non-fatal.
	_, _ = d.Pool.Exec(ctx, `
		UPDATE api_keys SET last_used_at = NOW() WHERE id = $1
	`, id)

	return true, nil
}
