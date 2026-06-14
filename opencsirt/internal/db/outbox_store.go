package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OutboxEntry mirrors the citadel_outbox table — every CITADEL event
// is persisted here first, then transitioned through pending → sending
// → sent (on durable confirmation) or failed.
type OutboxEntry struct {
	ID         uuid.UUID
	EventID    string
	EventType  string
	Payload    map[string]any
	State      string // pending|sending|sent|failed
	Attempts   int
	LastError  *string
	CreatedAt  time.Time
	SentAt     *time.Time
	TargetType string
	TargetID   *uuid.UUID
}

type OutboxStore struct{ pool *pgxpool.Pool }

func NewOutboxStore(pool *pgxpool.Pool) *OutboxStore { return &OutboxStore{pool: pool} }

func (s *OutboxStore) Enqueue(ctx context.Context, e *OutboxEntry) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.EventID == "" {
		e.EventID = uuid.NewString()
	}
	if e.State == "" {
		e.State = "pending"
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO citadel_outbox
		    (id, event_id, event_type, payload, state, attempts,
		     last_error, created_at, sent_at, target_type, target_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (event_id) DO NOTHING
	`, e.ID, e.EventID, e.EventType, payload, e.State, e.Attempts,
		e.LastError, e.CreatedAt, e.SentAt, e.TargetType, e.TargetID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Duplicate event_id: a prior enqueue for this deterministic key already
		// exists. Silently accept the no-op but surface it for observability.
		fmt.Printf("outbox: duplicate event skipped event_id=%s event_type=%s\n", e.EventID, e.EventType)
	}
	return nil
}

// Pending fetches up to `limit` entries in state=pending, oldest first.
// FOR UPDATE SKIP LOCKED is used so concurrent workers never see the same rows;
// MarkSending (called by the watcher immediately after) runs its UPDATE inside
// the same advisory window, and its WHERE state='pending' guard makes it
// idempotent-safe against any concurrent claim.
func (s *OutboxStore) Pending(ctx context.Context, limit int) ([]*OutboxEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT id, event_id, event_type, payload, state, attempts,
		       last_error, created_at, sent_at, target_type, target_id
		  FROM citadel_outbox
		 WHERE state = 'pending'
	     ORDER BY created_at ASC
	     LIMIT $1
	     FOR UPDATE SKIP LOCKED
	`, limit)
	if err != nil {
		return nil, err
	}
	out := []*OutboxEntry{}
	for rows.Next() {
		e := &OutboxEntry{}
		var payload []byte
		if err := rows.Scan(&e.ID, &e.EventID, &e.EventType, &payload, &e.State,
			&e.Attempts, &e.LastError, &e.CreatedAt, &e.SentAt,
			&e.TargetType, &e.TargetID); err != nil {
			rows.Close()
			return nil, err
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &e.Payload); err != nil {
				return nil, fmt.Errorf("unmarshal payload: %w", err)
			}
		}
		out = append(out, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit(ctx)
}

func (s *OutboxStore) MarkSending(ctx context.Context, id uuid.UUID, attempt int) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE citadel_outbox SET state = 'sending', attempts = $2 WHERE id = $1 AND state = 'pending'
	`, id, attempt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("outbox: row not in pending state")
	}
	return nil
}

func (s *OutboxStore) MarkSent(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE citadel_outbox SET state = 'sent', sent_at = $2 WHERE id = $1
	`, id, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *OutboxStore) MarkFailed(ctx context.Context, id uuid.UUID, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE citadel_outbox SET state = 'failed', last_error = $2 WHERE id = $1
	`, id, errMsg)
	return err
}

// RequeueSending resets any entries stuck in 'sending' after a crash back to
// 'pending' so they are retried. Safe to call on every startup.
func (s *OutboxStore) RequeueSending(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE citadel_outbox SET state = 'pending' WHERE state = 'sending'`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *OutboxStore) PendingCount(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM citadel_outbox WHERE state = 'pending'`).Scan(&n)
	return n, err
}

func (s *OutboxStore) FailedCount(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM citadel_outbox WHERE state = 'failed'`).Scan(&n)
	return n, err
}
