package webhook

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned by Get/Delete/Rotate when the subscriber id
// is unknown. Callers map this to HTTP 404.
var ErrNotFound = errors.New("webhook subscriber not found")

// Store is the persistence layer for subscribers + outbox. Backed by
// the shared pgxpool; Pool is exported so tests can swap it.
type Store struct {
	Pool *pgxpool.Pool
}

// NewStore wraps a pgxpool. Pool may be nil for tests that only
// exercise the dispatcher with a fake store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

// Upsert inserts or updates a subscriber by id. Mutates s.ID/CreatedAt
// when zero so callers can read them back.
func (s *Store) Upsert(ctx context.Context, sub *Subscriber) error {
	if s == nil || s.Pool == nil {
		return errors.New("webhook store: nil pool")
	}
	if sub.ID == uuid.Nil {
		sub.ID = uuid.New()
	}
	now := time.Now().UTC()
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = now
	}
	sub.UpdatedAt = now
	normaliseSlots(sub)

	_, err := s.Pool.Exec(ctx, `
		INSERT INTO webhook_subscribers_v2
		    (id, tenant, url, event_types, hmac_secrets, key_ids,
		     enabled, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE
		   SET tenant       = EXCLUDED.tenant,
		       url          = EXCLUDED.url,
		       event_types  = EXCLUDED.event_types,
		       hmac_secrets = EXCLUDED.hmac_secrets,
		       key_ids      = EXCLUDED.key_ids,
		       enabled      = EXCLUDED.enabled,
		       updated_at   = EXCLUDED.updated_at`,
		sub.ID, sub.Tenant, sub.URL, sub.EventTypes,
		sub.HMACSecrets, sub.KeyIDs, sub.Enabled,
		sub.CreatedAt, sub.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert webhook subscriber: %w", err)
	}
	return nil
}

// Get fetches one subscriber by id.
func (s *Store) Get(ctx context.Context, id uuid.UUID) (*Subscriber, error) {
	if s == nil || s.Pool == nil {
		return nil, errors.New("webhook store: nil pool")
	}
	row := s.Pool.QueryRow(ctx, `
		SELECT id, tenant, url, event_types, hmac_secrets, key_ids,
		       enabled, created_at, updated_at
		  FROM webhook_subscribers_v2 WHERE id = $1`, id)
	var sub Subscriber
	if err := row.Scan(
		&sub.ID, &sub.Tenant, &sub.URL, &sub.EventTypes,
		&sub.HMACSecrets, &sub.KeyIDs, &sub.Enabled,
		&sub.CreatedAt, &sub.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get webhook subscriber: %w", err)
	}
	return &sub, nil
}

// List returns all subscribers (any tenant). Callers filter further.
func (s *Store) List(ctx context.Context) ([]Subscriber, error) {
	if s == nil || s.Pool == nil {
		return nil, nil
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, tenant, url, event_types, hmac_secrets, key_ids,
		       enabled, created_at, updated_at
		  FROM webhook_subscribers_v2
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list webhook subscribers: %w", err)
	}
	defer rows.Close()
	out := make([]Subscriber, 0)
	for rows.Next() {
		var sub Subscriber
		if err := rows.Scan(
			&sub.ID, &sub.Tenant, &sub.URL, &sub.EventTypes,
			&sub.HMACSecrets, &sub.KeyIDs, &sub.Enabled,
			&sub.CreatedAt, &sub.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan webhook subscriber: %w", err)
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// ListByEventType returns enabled subscribers wanting eventType.
// Filtering is done in-memory after the SQL fetch — the GIN index on
// event_types accelerates the common case but the empty-array
// "match all" semantics don't translate cleanly to a single SQL pred.
func (s *Store) ListByEventType(ctx context.Context, eventType string) ([]Subscriber, error) {
	if s == nil || s.Pool == nil {
		return nil, nil
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, tenant, url, event_types, hmac_secrets, key_ids,
		       enabled, created_at, updated_at
		  FROM webhook_subscribers_v2
		 WHERE enabled = TRUE
		   AND (event_types = '{}'::text[] OR $1 = ANY(event_types))`,
		eventType)
	if err != nil {
		return nil, fmt.Errorf("list by event type: %w", err)
	}
	defer rows.Close()
	out := make([]Subscriber, 0)
	for rows.Next() {
		var sub Subscriber
		if err := rows.Scan(
			&sub.ID, &sub.Tenant, &sub.URL, &sub.EventTypes,
			&sub.HMACSecrets, &sub.KeyIDs, &sub.Enabled,
			&sub.CreatedAt, &sub.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// Delete removes a subscriber. Idempotent: missing id → ErrNotFound.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	if s == nil || s.Pool == nil {
		return errors.New("webhook store: nil pool")
	}
	tag, err := s.Pool.Exec(ctx,
		`DELETE FROM webhook_subscribers_v2 WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete webhook subscriber: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Rotate shifts the secret slots by one position: previous is dropped,
// next becomes primary, the supplied newSecret/newKeyID lands in next.
// Mirrors the documented rotation drill: stage NEXT, promote (this
// call) once consumers acknowledge the new key, then schedule the
// follow-up rotate to age out the previous slot.
func (s *Store) Rotate(ctx context.Context, id uuid.UUID, newSecret, newKeyID string) (*Subscriber, error) {
	if s == nil || s.Pool == nil {
		return nil, errors.New("webhook store: nil pool")
	}
	if newSecret == "" {
		return nil, errors.New("webhook rotate: new secret is empty")
	}
	sub, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	normaliseSlots(sub)
	// Shift: previous = next, primary = next (kept as primary if next
	// was empty — first-time rotation just lands the new key in NEXT).
	prevPrev := sub.HMACSecrets[SlotPrevious]
	prevPrevID := sub.KeyIDs[SlotPrevious]
	_ = prevPrev
	_ = prevPrevID
	// Move primary → previous, next → primary, new → next.
	sub.HMACSecrets[SlotPrevious] = sub.HMACSecrets[SlotPrimary]
	sub.KeyIDs[SlotPrevious] = sub.KeyIDs[SlotPrimary]
	if sub.HMACSecrets[SlotNext] != "" {
		sub.HMACSecrets[SlotPrimary] = sub.HMACSecrets[SlotNext]
		sub.KeyIDs[SlotPrimary] = sub.KeyIDs[SlotNext]
	}
	sub.HMACSecrets[SlotNext] = newSecret
	sub.KeyIDs[SlotNext] = newKeyID
	if err := s.Upsert(ctx, sub); err != nil {
		return nil, err
	}
	return sub, nil
}

// EnqueueOutbox persists an event-per-subscriber row. Caller is
// expected to wrap this in the same DB transaction as the originating
// business write when ordering matters (outbox pattern).
func (s *Store) EnqueueOutbox(ctx context.Context, row *OutboxRow) error {
	if s == nil || s.Pool == nil {
		return errors.New("webhook store: nil pool")
	}
	if row.ID == uuid.Nil {
		row.ID = uuid.New()
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	if row.NextAttemptAt.IsZero() {
		row.NextAttemptAt = row.CreatedAt
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO webhook_outbox
		    (id, subscriber_id, event_id, event_type, payload,
		     attempts, last_error, next_attempt_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		row.ID, row.SubscriberID, row.EventID, row.EventType,
		row.Payload, row.Attempts, row.LastError,
		row.NextAttemptAt, row.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("enqueue outbox: %w", err)
	}
	return nil
}

// FetchPendingOutbox returns up-to-limit undelivered rows whose
// next_attempt_at has fired. Ordered FIFO.
func (s *Store) FetchPendingOutbox(ctx context.Context, limit int) ([]OutboxRow, error) {
	if s == nil || s.Pool == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, subscriber_id, event_id, event_type, payload,
		       attempts, last_error, next_attempt_at, delivered_at, created_at
		  FROM webhook_outbox
		 WHERE delivered_at IS NULL AND next_attempt_at <= NOW()
		 ORDER BY created_at ASC
		 LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("fetch pending outbox: %w", err)
	}
	defer rows.Close()
	out := make([]OutboxRow, 0)
	for rows.Next() {
		var r OutboxRow
		if err := rows.Scan(
			&r.ID, &r.SubscriberID, &r.EventID, &r.EventType, &r.Payload,
			&r.Attempts, &r.LastError, &r.NextAttemptAt, &r.DeliveredAt, &r.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan outbox: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkDelivered stamps delivered_at = now.
func (s *Store) MarkDelivered(ctx context.Context, id uuid.UUID) error {
	if s == nil || s.Pool == nil {
		return errors.New("webhook store: nil pool")
	}
	_, err := s.Pool.Exec(ctx,
		`UPDATE webhook_outbox SET delivered_at = NOW() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("mark delivered: %w", err)
	}
	return nil
}

// MarkAttempt bumps attempts, records last error, and pushes
// next_attempt_at out by backoff.
func (s *Store) MarkAttempt(ctx context.Context, id uuid.UUID, attemptErr string, backoff time.Duration) error {
	if s == nil || s.Pool == nil {
		return errors.New("webhook store: nil pool")
	}
	_, err := s.Pool.Exec(ctx, `
		UPDATE webhook_outbox
		   SET attempts        = attempts + 1,
		       last_error      = $2,
		       next_attempt_at = NOW() + $3::interval
		 WHERE id = $1`,
		id, attemptErr, fmt.Sprintf("%d milliseconds", backoff.Milliseconds()))
	if err != nil {
		return fmt.Errorf("mark attempt: %w", err)
	}
	return nil
}

// OutboxSize returns count of undelivered rows. Used by metrics gauge.
func (s *Store) OutboxSize(ctx context.Context) (int, error) {
	if s == nil || s.Pool == nil {
		return 0, nil
	}
	var n int
	err := s.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM webhook_outbox WHERE delivered_at IS NULL`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("outbox size: %w", err)
	}
	return n, nil
}

// normaliseSlots pads HMACSecrets/KeyIDs to NumSlots so callers can
// index unconditionally. Done in-place.
func normaliseSlots(sub *Subscriber) {
	for len(sub.HMACSecrets) < NumSlots {
		sub.HMACSecrets = append(sub.HMACSecrets, "")
	}
	for len(sub.KeyIDs) < NumSlots {
		sub.KeyIDs = append(sub.KeyIDs, "")
	}
	if len(sub.HMACSecrets) > NumSlots {
		sub.HMACSecrets = sub.HMACSecrets[:NumSlots]
	}
	if len(sub.KeyIDs) > NumSlots {
		sub.KeyIDs = sub.KeyIDs[:NumSlots]
	}
}
