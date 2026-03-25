package db

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AppendAuditLog inserts a new audit log entry with CITADEL chain-hash integrity.
//
// The fetch of the previous chain_hash and the INSERT are executed inside a
// single serializable transaction protected by a PostgreSQL advisory lock
// (pg_advisory_xact_lock). This prevents two concurrent goroutines from racing
// to become the "previous" entry and breaking the chain.
func (d *DB) AppendAuditLog(ctx context.Context, entry *AuditLog) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning audit log transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Serialise all audit_log writes through a single advisory lock so that
	// the fetch-then-insert is atomic with respect to other appenders.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('apiguard_audit_chain'))`); err != nil {
		return fmt.Errorf("acquiring audit chain lock: %w", err)
	}

	// Fetch the most recent chain_hash to anchor this entry.
	var prevHash *string
	var lastHash string
	if err := tx.QueryRow(ctx,
		`SELECT chain_hash FROM audit_log ORDER BY created_at DESC, id DESC LIMIT 1`,
	).Scan(&lastHash); err == nil {
		prevHash = &lastHash
	}

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

	var beforeState, afterState interface{}
	if len(entry.BeforeState) > 0 {
		beforeState = entry.BeforeState
	}
	if len(entry.AfterState) > 0 {
		afterState = entry.AfterState
	}

	if _, err := tx.Exec(ctx, `
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
	); err != nil {
		return fmt.Errorf("inserting audit log entry: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing audit log transaction: %w", err)
	}

	entry.ID = id
	entry.PrevHash = prevHash
	entry.ChainHash = chainHash
	entry.CreatedAt = now
	return nil
}
