package store

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

// WebhookSubscriber is a row in webhook_subscribers.
type WebhookSubscriber struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Platform      string    `json:"platform"`
	URL           string    `json:"url"`
	Secret        string    `json:"-"`
	EventTypes    []string  `json:"event_types"`
	MinConfidence int       `json:"min_confidence"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// WebhookDelivery is a row in webhook_deliveries.
type WebhookDelivery struct {
	ID            uuid.UUID       `json:"id"`
	SubscriberID  uuid.UUID       `json:"subscriber_id"`
	EventType     string          `json:"event_type"`
	EventID       uuid.UUID       `json:"event_id"`
	Payload       json.RawMessage `json:"payload"`
	Status        string          `json:"status"`
	AttemptCount  int             `json:"attempt_count"`
	LastStatus    *int            `json:"last_status,omitempty"`
	LastError     string          `json:"last_error,omitempty"`
	LastAttemptAt *time.Time      `json:"last_attempt_at,omitempty"`
	DeliveredAt   *time.Time      `json:"delivered_at,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// WebhookStore persists webhook_subscribers and webhook_deliveries rows.
type WebhookStore struct {
	pool *pgxpool.Pool
}

// NewWebhookStore binds a store to the pool.
func NewWebhookStore(pool *pgxpool.Pool) *WebhookStore {
	return &WebhookStore{pool: pool}
}

// CreateSubscriber inserts a new subscriber.
func (s *WebhookStore) CreateSubscriber(ctx context.Context, sub *WebhookSubscriber) error {
	if sub.EventTypes == nil {
		sub.EventTypes = []string{}
	}
	const q = `
INSERT INTO webhook_subscribers (name, platform, url, secret, event_types, min_confidence, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, created_at, updated_at`
	return s.pool.QueryRow(ctx, q,
		sub.Name, sub.Platform, sub.URL, sub.Secret, sub.EventTypes,
		sub.MinConfidence, sub.Enabled,
	).Scan(&sub.ID, &sub.CreatedAt, &sub.UpdatedAt)
}

// GetSubscriber fetches a subscriber by ID.
func (s *WebhookStore) GetSubscriber(ctx context.Context, id uuid.UUID) (*WebhookSubscriber, error) {
	const q = `
SELECT id, name, platform, url, secret, event_types, min_confidence, enabled, created_at, updated_at
FROM webhook_subscribers WHERE id = $1`
	var sub WebhookSubscriber
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&sub.ID, &sub.Name, &sub.Platform, &sub.URL, &sub.Secret,
		&sub.EventTypes, &sub.MinConfidence, &sub.Enabled,
		&sub.CreatedAt, &sub.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &sub, err
}

// ListSubscribers returns every subscriber row.
func (s *WebhookStore) ListSubscribers(ctx context.Context, enabledOnly bool) ([]*WebhookSubscriber, error) {
	q := `
SELECT id, name, platform, url, secret, event_types, min_confidence, enabled, created_at, updated_at
FROM webhook_subscribers`
	if enabledOnly {
		q += " WHERE enabled = TRUE"
	}
	q += " ORDER BY name"

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*WebhookSubscriber
	for rows.Next() {
		var sub WebhookSubscriber
		if err := rows.Scan(
			&sub.ID, &sub.Name, &sub.Platform, &sub.URL, &sub.Secret,
			&sub.EventTypes, &sub.MinConfidence, &sub.Enabled,
			&sub.CreatedAt, &sub.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, &sub)
	}
	return out, rows.Err()
}

// MatchingSubscribers returns enabled subscribers whose event_types contain
// the given eventType (or is empty, meaning "subscribe to all") AND whose
// min_confidence threshold is met.
func (s *WebhookStore) MatchingSubscribers(ctx context.Context, eventType string, confidence int) ([]*WebhookSubscriber, error) {
	const q = `
SELECT id, name, platform, url, secret, event_types, min_confidence, enabled, created_at, updated_at
FROM webhook_subscribers
WHERE enabled = TRUE
  AND (event_types = '{}' OR $1 = ANY(event_types))
  AND $2 >= min_confidence`
	rows, err := s.pool.Query(ctx, q, eventType, confidence)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*WebhookSubscriber
	for rows.Next() {
		var sub WebhookSubscriber
		if err := rows.Scan(
			&sub.ID, &sub.Name, &sub.Platform, &sub.URL, &sub.Secret,
			&sub.EventTypes, &sub.MinConfidence, &sub.Enabled,
			&sub.CreatedAt, &sub.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, &sub)
	}
	return out, rows.Err()
}

// SetEnabled toggles a subscriber.
func (s *WebhookStore) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE webhook_subscribers SET enabled = $1, updated_at = now() WHERE id = $2`, enabled, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSubscriber removes a subscriber and cascades its deliveries.
func (s *WebhookStore) DeleteSubscriber(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM webhook_subscribers WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordDelivery upserts a delivery row keyed on (subscriber_id, event_id) so
// retries of the same event reuse the same row.
func (s *WebhookStore) RecordDelivery(ctx context.Context, d *WebhookDelivery) error {
	if len(d.Payload) == 0 {
		d.Payload = json.RawMessage(`{}`)
	}
	const q = `
INSERT INTO webhook_deliveries (
    subscriber_id, event_type, event_id, payload, status,
    attempt_count, last_status, last_error, last_attempt_at, delivered_at
) VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10)
ON CONFLICT (subscriber_id, event_id) DO UPDATE SET
    status          = EXCLUDED.status,
    attempt_count   = webhook_deliveries.attempt_count + 1,
    last_status     = EXCLUDED.last_status,
    last_error      = EXCLUDED.last_error,
    last_attempt_at = EXCLUDED.last_attempt_at,
    delivered_at    = COALESCE(webhook_deliveries.delivered_at, EXCLUDED.delivered_at)
RETURNING id, attempt_count, created_at`
	lastErr := any(nil)
	if d.LastError != "" {
		lastErr = d.LastError
	}
	return s.pool.QueryRow(ctx, q,
		d.SubscriberID, d.EventType, d.EventID, d.Payload, d.Status,
		d.AttemptCount, d.LastStatus, lastErr, d.LastAttemptAt, d.DeliveredAt,
	).Scan(&d.ID, &d.AttemptCount, &d.CreatedAt)
}

// RecentDeliveries returns the N most recent deliveries for a subscriber.
func (s *WebhookStore) RecentDeliveries(ctx context.Context, subscriberID uuid.UUID, limit int) ([]*WebhookDelivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	const q = `
SELECT id, subscriber_id, event_type, event_id, payload::text, status, attempt_count,
       last_status, coalesce(last_error, ''), last_attempt_at, delivered_at, created_at
FROM webhook_deliveries
WHERE subscriber_id = $1
ORDER BY created_at DESC
LIMIT $2`
	rows, err := s.pool.Query(ctx, q, subscriberID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*WebhookDelivery
	for rows.Next() {
		var (
			d           WebhookDelivery
			payloadText string
		)
		if err := rows.Scan(
			&d.ID, &d.SubscriberID, &d.EventType, &d.EventID, &payloadText,
			&d.Status, &d.AttemptCount, &d.LastStatus, &d.LastError,
			&d.LastAttemptAt, &d.DeliveredAt, &d.CreatedAt,
		); err != nil {
			return nil, err
		}
		d.Payload = json.RawMessage(payloadText)
		out = append(out, &d)
	}
	return out, rows.Err()
}

// DeliveryStats aggregates counts by status.
func (s *WebhookStore) DeliveryStats(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT status, count(*)::int FROM webhook_deliveries GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("stats: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var c int
		if err := rows.Scan(&s, &c); err != nil {
			return nil, err
		}
		out[s] = c
	}
	return out, rows.Err()
}
