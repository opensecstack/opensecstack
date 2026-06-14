// Package db — webhook_store manages `webhooks`.
// Outbound webhook subscribers; HMAC-SHA256 signed deliveries.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Webhook mirrors a row in `webhooks`.
type Webhook struct {
	ID                  uuid.UUID  `json:"id"`
	TenantID            uuid.UUID  `json:"tenant_id"`
	Name                string     `json:"name"`
	URL                 string     `json:"url"`
	EventTypes          []string   `json:"event_types"`
	SecretHMAC          string     `json:"-"`
	SecretVersion       int        `json:"secret_version"`
	Active              bool       `json:"active"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastSuccessAt       *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt       *time.Time `json:"last_failure_at,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
}

// WebhookStore wraps a pgx pool for `webhooks`.
type WebhookStore struct {
	Pool *pgxpool.Pool
}

// NewWebhookStore wires a WebhookStore.
func NewWebhookStore(pool *pgxpool.Pool) *WebhookStore { return &WebhookStore{Pool: pool} }

const webhookColumns = `id, tenant_id, name, url, event_types,
	secret_hmac, secret_version, active, created_at, updated_at,
	last_success_at, last_failure_at, consecutive_failures`

func scanWebhook(row pgx.Row) (*Webhook, error) {
	var w Webhook
	if err := row.Scan(
		&w.ID, &w.TenantID, &w.Name, &w.URL, &w.EventTypes,
		&w.SecretHMAC, &w.SecretVersion, &w.Active, &w.CreatedAt, &w.UpdatedAt,
		&w.LastSuccessAt, &w.LastFailureAt, &w.ConsecutiveFailures,
	); err != nil {
		return nil, err
	}
	return &w, nil
}

// Create inserts a new webhook subscription.
func (s *WebhookStore) Create(ctx context.Context, w *Webhook) (*Webhook, error) {
	const op = "webhook.Create"
	if w.ID == uuid.Nil {
		w.ID = uuid.New()
	}
	if w.EventTypes == nil {
		w.EventTypes = []string{}
	}
	if w.SecretVersion == 0 {
		w.SecretVersion = 1
	}
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO webhooks (
			id, tenant_id, name, url, event_types,
			secret_hmac, secret_version, active
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING `+webhookColumns,
		w.ID, w.TenantID, w.Name, w.URL, w.EventTypes,
		w.SecretHMAC, w.SecretVersion, w.Active,
	)
	out, err := scanWebhook(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// Get returns a webhook by id.
func (s *WebhookStore) Get(ctx context.Context, id uuid.UUID) (*Webhook, error) {
	const op = "webhook.Get"
	row := s.Pool.QueryRow(ctx, `SELECT `+webhookColumns+` FROM webhooks WHERE id = $1`, id)
	out, err := scanWebhook(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// ListByTenant returns webhooks for a tenant; if activeOnly is true, only active rows.
func (s *WebhookStore) ListByTenant(ctx context.Context, tenantID uuid.UUID, activeOnly bool) ([]Webhook, error) {
	const op = "webhook.ListByTenant"
	q := `SELECT ` + webhookColumns + ` FROM webhooks WHERE tenant_id = $1`
	if activeOnly {
		q += ` AND active = TRUE`
	}
	q += ` ORDER BY created_at DESC`

	rows, err := s.Pool.Query(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Webhook, 0, 8)
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}

// Update overwrites mutable webhook fields (not the secret — see RotateSecret).
func (s *WebhookStore) Update(ctx context.Context, w *Webhook) (*Webhook, error) {
	const op = "webhook.Update"
	if w.EventTypes == nil {
		w.EventTypes = []string{}
	}
	row := s.Pool.QueryRow(ctx, `
		UPDATE webhooks SET
			name        = $2,
			url         = $3,
			event_types = $4,
			active      = $5,
			updated_at  = now()
		WHERE id = $1
		RETURNING `+webhookColumns,
		w.ID, w.Name, w.URL, w.EventTypes, w.Active,
	)
	out, err := scanWebhook(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// RecordSuccess clears the failure counter and bumps last_success_at.
func (s *WebhookStore) RecordSuccess(ctx context.Context, id uuid.UUID) error {
	const op = "webhook.RecordSuccess"
	_, err := s.Pool.Exec(ctx, `
		UPDATE webhooks
		SET last_success_at = now(), consecutive_failures = 0
		WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}

// RecordFailure increments consecutive_failures and stamps last_failure_at.
// errMsg is currently advisory — there's no column on webhooks for it; the
// authoritative failure log lives in `outbox.last_error`.
func (s *WebhookStore) RecordFailure(ctx context.Context, id uuid.UUID, errMsg string) error {
	const op = "webhook.RecordFailure"
	_ = errMsg // recorded on the outbox row, not the webhook
	_, err := s.Pool.Exec(ctx, `
		UPDATE webhooks
		SET last_failure_at = now(), consecutive_failures = consecutive_failures + 1
		WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}

// RotateSecret swaps in a new HMAC secret and bumps secret_version.
// Caller is responsible for the 24h overlap window during which the
// previous secret remains accepted (delivery worker policy).
func (s *WebhookStore) RotateSecret(ctx context.Context, id uuid.UUID, newSecret string) error {
	const op = "webhook.RotateSecret"
	_, err := s.Pool.Exec(ctx, `
		UPDATE webhooks
		SET secret_hmac = $2, secret_version = secret_version + 1, updated_at = now()
		WHERE id = $1`, id, newSecret)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}
