package db

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"
)

// RegisterKey binds an Ed25519 public key (hex-encoded) to userID (a sinauth
// UUID) under keyID. Callers (internal/api/handlers/keys.go) are
// responsible for verifying the requester actually owns userID (via a
// verified sinauth bearer token) before calling this — RegisterKey itself
// performs no identity check.
func (d *DB) RegisterKey(ctx context.Context, userID, keyID, publicKeyHex string) error {
	raw, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("db: RegisterKey: public_key must be %d hex-encoded bytes", ed25519.PublicKeySize)
	}

	_, err = d.Pool.Exec(ctx,
		`INSERT INTO signing_keys (user_id, key_id, public_key)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, key_id) DO UPDATE SET public_key = EXCLUDED.public_key, revoked_at = NULL`,
		userID, keyID, publicKeyHex,
	)
	if err != nil {
		return fmt.Errorf("db: RegisterKey: insert: %w", err)
	}
	return nil
}

// GetActiveKey returns the non-revoked Ed25519 public key registered for
// userID. exists is false if the user has no active key.
func (d *DB) GetActiveKey(ctx context.Context, userID string) (pubKey ed25519.PublicKey, keyID string, exists bool, err error) {
	var pkHex string
	row := d.Pool.QueryRow(ctx,
		`SELECT key_id, public_key FROM signing_keys
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at DESC
		 LIMIT 1`,
		userID,
	)
	if scanErr := row.Scan(&keyID, &pkHex); scanErr != nil {
		return nil, "", false, nil
	}

	raw, decErr := hex.DecodeString(pkHex)
	if decErr != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "", false, fmt.Errorf("db: GetActiveKey: stored public_key for user_id=%s is malformed", userID)
	}
	return ed25519.PublicKey(raw), keyID, true, nil
}

// GetActiveKeyID returns the key_id and registration time of userID's
// active signing key, without decoding the public key bytes. Used by the
// GET /api/v1/keys/{user_id} lookup endpoint.
func (d *DB) GetActiveKeyID(ctx context.Context, userID string) (keyID string, registeredAt time.Time, exists bool, err error) {
	row := d.Pool.QueryRow(ctx,
		`SELECT key_id, created_at FROM signing_keys
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at DESC
		 LIMIT 1`,
		userID,
	)
	if scanErr := row.Scan(&keyID, &registeredAt); scanErr != nil {
		return "", time.Time{}, false, nil
	}
	return keyID, registeredAt, true, nil
}

// RevokeKey marks keyID for userID as revoked (does not delete the row —
// signing_keys is evidence of what could verify a past WORM entry).
func (d *DB) RevokeKey(ctx context.Context, userID string, keyID string) error {
	_, err := d.Pool.Exec(ctx,
		`UPDATE signing_keys SET revoked_at = $3
		 WHERE user_id = $1 AND key_id = $2 AND revoked_at IS NULL`,
		userID, keyID, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("db: RevokeKey: %w", err)
	}
	return nil
}
