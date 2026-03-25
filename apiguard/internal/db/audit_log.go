package db

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AppendAuditLog inserts a new audit log entry with CITADEL chain-hash integrity.
// It fetches the previous row's chain_hash (prev_hash), computes the new
// chain_hash as SHA-256(id|actor_id|action|resource_id|prev_hash|created_at),
// and inserts the immutable record.
func (d *DB) AppendAuditLog(ctx context.Context, entry *AuditLog) error {
	// Fetch the most recent chain_hash to anchor the chain.
	var prevHash *string
	var lastHash string
	err := d.Pool.QueryRow(ctx,
		`SELECT chain_hash FROM audit_log ORDER BY created_at DESC, id DESC LIMIT 1`,
	).Scan(&lastHash)
	if err == nil {
		prevHash = &lastHash
	}
	// If no rows yet, prevHash stays nil (NULL in DB — valid for the genesis entry).

	id := uuid.New()
	now := time.Now().UTC()

	resourceIDStr := ""
	if entry.ResourceID != nil {
		resourceIDStr = entry.ResourceID.String()
	}

	prevHashStr := ""
	if prevHash != nil {
		prevHashStr = *prevHash
	}

	// chain_hash = SHA-256(id|actor_id|action|resource_id|prev_hash|created_at)
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s",
		id.String(),
		entry.ActorID,
		string(entry.Action),
		resourceIDStr,
		prevHashStr,
		now.Format(time.RFC3339Nano),
	)
	chainHash := fmt.Sprintf("%x", h.Sum(nil))

	metaJSON := entry.Metadata
	if metaJSON == nil {
		metaJSON = []byte("{}")
	}

	// Use nil for NULL JSONB columns when the caller didn't provide state diffs.
	var beforeState, afterState interface{}
	if len(entry.BeforeState) > 0 {
		beforeState = entry.BeforeState
	}
	if len(entry.AfterState) > 0 {
		afterState = entry.AfterState
	}

	_, err = d.Pool.Exec(ctx, `
		INSERT INTO audit_log (
			id, actor_id, actor_type, action, resource_type, resource_id,
			ip_address, user_agent, before_state, after_state, metadata,
			prev_hash, chain_hash, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14
		)`,
		id,
		entry.ActorID,
		entry.ActorType,
		string(entry.Action),
		entry.ResourceType,
		entry.ResourceID,
		entry.IPAddress,
		entry.UserAgent,
		beforeState,
		afterState,
		metaJSON,
		prevHash,
		chainHash,
		now,
	)
	if err != nil {
		return fmt.Errorf("inserting audit log entry: %w", err)
	}

	entry.ID = id
	entry.PrevHash = prevHash
	entry.ChainHash = chainHash
	entry.CreatedAt = now
	return nil
}
