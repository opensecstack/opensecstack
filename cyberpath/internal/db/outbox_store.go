// Package db — outbox_store manages the transactional `outbox` queue.
// CITADEL submissions + reliable webhook delivery share this queue.
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OutboxEntry mirrors a row in `outbox`. ID is BIGINT IDENTITY.
type OutboxEntry struct {
	ID            int64           `json:"id"`
	TenantID      *uuid.UUID      `json:"tenant_id,omitempty"`
	Destination   string          `json:"destination"`
	WebhookID     *uuid.UUID      `json:"webhook_id,omitempty"`
	EventType     string          `json:"event_type"`
	Payload       json.RawMessage `json:"payload"`
	CorrelationID string          `json:"correlation_id,omitempty"`
	Status        string          `json:"status"`
	Attempts      int             `json:"attempts"`
	NextAttemptAt time.Time       `json:"next_attempt_at"`
	LastError     string          `json:"last_error,omitempty"`
	DeliveredAt   *time.Time      `json:"delivered_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// OutboxStore wraps a pgx pool for the outbox table.
//
// Worker contract (matches the SQL comments on the table):
//  1. Worker calls Claim(ctx, batchSize). It atomically selects pending
//     rows whose next_attempt_at <= now() with FOR UPDATE SKIP LOCKED,
//     flips them to status='in_flight', and returns the rows.
//  2. Worker delivers each row (POST + HMAC).
//  3. On 2xx → MarkDelivered(id). On error → MarkFailed(id, errMsg);
//     row is requeued with exponential backoff or moved to 'dlq' after
//     >10 attempts.
//  4. Operators triage 'dlq' rows via DLQ() and may RequeueFromDLQ() them.
//  5. GCDelivered() runs nightly to enforce the 90-day retention sweep.
type OutboxStore struct {
	Pool *pgxpool.Pool
}

// NewOutboxStore wires an OutboxStore.
func NewOutboxStore(pool *pgxpool.Pool) *OutboxStore { return &OutboxStore{Pool: pool} }

const outboxColumns = `id, tenant_id, destination, webhook_id, event_type, payload,
	correlation_id, status, attempts, next_attempt_at,
	last_error, delivered_at, created_at`

func scanOutbox(row pgx.Row) (*OutboxEntry, error) {
	var e OutboxEntry
	var lastErr *string
	var corr *string
	if err := row.Scan(
		&e.ID, &e.TenantID, &e.Destination, &e.WebhookID, &e.EventType, &e.Payload,
		&corr, &e.Status, &e.Attempts, &e.NextAttemptAt,
		&lastErr, &e.DeliveredAt, &e.CreatedAt,
	); err != nil {
		return nil, err
	}
	if corr != nil {
		e.CorrelationID = *corr
	}
	if lastErr != nil {
		e.LastError = *lastErr
	}
	return &e, nil
}

// Enqueue inserts a new outbox row in 'pending' status. Returns the assigned ID.
func (s *OutboxStore) Enqueue(ctx context.Context, e *OutboxEntry) (int64, error) {
	const op = "outbox.Enqueue"
	if len(e.Payload) == 0 {
		e.Payload = []byte("{}")
	}
	if e.Status == "" {
		e.Status = "pending"
	}
	var id int64
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO outbox (
			tenant_id, destination, webhook_id, event_type, payload,
			correlation_id, status
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id`,
		nullableUUID(e.TenantID), e.Destination, nullableUUID(e.WebhookID),
		e.EventType, []byte(e.Payload), nullableString(e.CorrelationID), e.Status,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("store/%s: %w", op, err)
	}
	e.ID = id
	return id, nil
}

// Claim atomically claims up to batchSize pending rows whose next_attempt_at
// has passed, flips them to 'in_flight', and returns them. Uses
// FOR UPDATE SKIP LOCKED so multiple workers can run safely in parallel.
func (s *OutboxStore) Claim(ctx context.Context, batchSize int) ([]OutboxEntry, error) {
	const op = "outbox.Claim"
	if batchSize <= 0 {
		batchSize = 16
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("store/%s: begin: %w", op, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Select+lock the candidate ids.
	rows, err := tx.Query(ctx, `
		SELECT id FROM outbox
		WHERE status = 'pending' AND next_attempt_at <= now()
		ORDER BY id
		FOR UPDATE SKIP LOCKED
		LIMIT $1`, batchSize)
	if err != nil {
		return nil, fmt.Errorf("store/%s: select: %w", op, err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store/%s: scan id: %w", op, err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	if len(ids) == 0 {
		_ = tx.Commit(ctx)
		return nil, nil
	}

	// Flip to in_flight and return the full rows.
	upd, err := tx.Query(ctx, `
		UPDATE outbox SET status = 'in_flight'
		WHERE id = ANY($1::bigint[])
		RETURNING `+outboxColumns, ids)
	if err != nil {
		return nil, fmt.Errorf("store/%s: update: %w", op, err)
	}
	out := make([]OutboxEntry, 0, len(ids))
	for upd.Next() {
		e, err := scanOutbox(upd)
		if err != nil {
			upd.Close()
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *e)
	}
	upd.Close()
	if err := upd.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: upd rows: %w", op, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("store/%s: commit: %w", op, err)
	}
	return out, nil
}

// MarkDelivered finalises a successfully delivered row.
func (s *OutboxStore) MarkDelivered(ctx context.Context, id int64) error {
	const op = "outbox.MarkDelivered"
	_, err := s.Pool.Exec(ctx, `
		UPDATE outbox SET status = 'delivered', delivered_at = now(), last_error = NULL
		WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}

// MarkFailed bumps attempts, records the error, and either reschedules the
// row with exponential backoff (2^attempts seconds, capped at 1h) or sends
// it to the DLQ if attempts exceeds 10.
func (s *OutboxStore) MarkFailed(ctx context.Context, id int64, errMsg string) error {
	const op = "outbox.MarkFailed"
	// Cap at 3600s (1h). Single SQL statement so it's atomic with the
	// attempts increment; LEAST + POWER does the backoff math in DB.
	_, err := s.Pool.Exec(ctx, `
		UPDATE outbox SET
			attempts        = attempts + 1,
			last_error      = $2,
			status          = CASE WHEN attempts + 1 > 10 THEN 'dlq' ELSE 'pending' END,
			next_attempt_at = now() + (LEAST(POWER(2, attempts + 1), 3600) || ' seconds')::interval
		WHERE id = $1`, id, errMsg)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}

// DLQ returns rows currently in the dead-letter queue, oldest first.
func (s *OutboxStore) DLQ(ctx context.Context, limit, offset int) ([]OutboxEntry, error) {
	const op = "outbox.DLQ"
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT `+outboxColumns+` FROM outbox
		WHERE status = 'dlq'
		ORDER BY id
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]OutboxEntry, 0, limit)
	for rows.Next() {
		e, err := scanOutbox(rows)
		if err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}

// RequeueFromDLQ resets a DLQ row back to 'pending' for immediate retry,
// zeroing attempts so the backoff ladder restarts.
func (s *OutboxStore) RequeueFromDLQ(ctx context.Context, id int64) error {
	const op = "outbox.RequeueFromDLQ"
	_, err := s.Pool.Exec(ctx, `
		UPDATE outbox SET
			status          = 'pending',
			attempts        = 0,
			next_attempt_at = now(),
			last_error      = NULL
		WHERE id = $1 AND status = 'dlq'`, id)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}

// GCDelivered deletes 'delivered' rows whose delivered_at is older than the
// supplied retention horizon. Returns the number of rows removed. Intended
// to be called from a nightly cron (default horizon: 90 days).
func (s *OutboxStore) GCDelivered(ctx context.Context, olderThan time.Duration) (int64, error) {
	const op = "outbox.GCDelivered"
	cmd, err := s.Pool.Exec(ctx, `
		DELETE FROM outbox
		WHERE status = 'delivered' AND delivered_at < now() - $1::interval`,
		fmt.Sprintf("%d seconds", int64(olderThan.Seconds())))
	if err != nil {
		return 0, fmt.Errorf("store/%s: %w", op, err)
	}
	return cmd.RowsAffected(), nil
}
