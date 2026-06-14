// Package db — audit_event_store manages `audit_events`.
// Append-only generic audit log; retention is 7 years (NIS2 default).
package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEvent mirrors a row in `audit_events`.
//
// IPAddress is mapped to a Go string. The DB column is INET; we read it
// via host(ip_address)::text to avoid pulling in netip-specific pgx
// codecs, and write it as a plain string which pgx coerces to inet.
// An empty string round-trips as SQL NULL on write.
type AuditEvent struct {
	ID            uuid.UUID       `json:"id"`
	TenantID      *uuid.UUID      `json:"tenant_id,omitempty"`
	ActorUserID   *uuid.UUID      `json:"actor_user_id,omitempty"`
	ActorRole     string          `json:"actor_role"`
	Action        string          `json:"action"`
	TargetType    string          `json:"target_type,omitempty"`
	TargetID      string          `json:"target_id,omitempty"`
	Outcome       string          `json:"outcome"`
	Metadata      json.RawMessage `json:"metadata"`
	CorrelationID string          `json:"correlation_id,omitempty"`
	IPAddress     string          `json:"ip_address,omitempty"`
	UserAgent     string          `json:"user_agent,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// AuditEventStore wraps a pgx pool. Reads + Append; no update/delete API.
type AuditEventStore struct {
	Pool *pgxpool.Pool
}

// NewAuditEventStore wires an AuditEventStore.
func NewAuditEventStore(pool *pgxpool.Pool) *AuditEventStore { return &AuditEventStore{Pool: pool} }

// AuditFilter narrows a Query/Count call. Zero-value fields are omitted.
type AuditFilter struct {
	TenantID    *uuid.UUID
	ActorUserID *uuid.UUID
	Action      string
	TargetType  string
	From        *time.Time
	To          *time.Time
	Limit       int
	Offset      int
}

// Append inserts one audit row. Mutates e.ID/e.CreatedAt only when unset.
func (s *AuditEventStore) Append(ctx context.Context, e *AuditEvent) error {
	const op = "audit.Append"
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if len(e.Metadata) == 0 {
		e.Metadata = []byte("{}")
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO audit_events (
			id, tenant_id, actor_user_id, actor_role, action,
			target_type, target_id, outcome, metadata,
			correlation_id, ip_address, user_agent, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, COALESCE($13, now()))`,
		e.ID, nullableUUID(e.TenantID), nullableUUID(e.ActorUserID),
		e.ActorRole, e.Action,
		nullableString(e.TargetType), nullableString(e.TargetID), e.Outcome, []byte(e.Metadata),
		nullableString(e.CorrelationID), nullableString(e.IPAddress), nullableString(e.UserAgent),
		nullableTime(zeroIfDefault(e.CreatedAt)),
	)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}

// zeroIfDefault returns nil if t is the zero value (so DB DEFAULT now() applies).
func zeroIfDefault(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (f AuditFilter) where() (string, []any) {
	var conds []string
	var args []any
	add := func(expr string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(expr, len(args)))
	}
	if f.TenantID != nil {
		add("tenant_id = $%d", *f.TenantID)
	}
	if f.ActorUserID != nil {
		add("actor_user_id = $%d", *f.ActorUserID)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.TargetType != "" {
		add("target_type = $%d", f.TargetType)
	}
	if f.From != nil {
		add("created_at >= $%d", *f.From)
	}
	if f.To != nil {
		add("created_at < $%d", *f.To)
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// Query returns rows matching the filter, newest first.
func (s *AuditEventStore) Query(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	const op = "audit.Query"
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	where, args := f.where()
	q := `SELECT id, tenant_id, actor_user_id, actor_role, action,
	             COALESCE(target_type,''), COALESCE(target_id,''),
	             outcome, metadata,
	             COALESCE(correlation_id,''),
	             COALESCE(host(ip_address),''),
	             COALESCE(user_agent,''),
	             created_at
	      FROM audit_events` + where +
		fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, f.Offset)

	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]AuditEvent, 0, limit)
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(
			&e.ID, &e.TenantID, &e.ActorUserID, &e.ActorRole, &e.Action,
			&e.TargetType, &e.TargetID, &e.Outcome, &e.Metadata,
			&e.CorrelationID, &e.IPAddress, &e.UserAgent, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}

// Count returns the total number of rows matching the filter (ignores limit/offset).
func (s *AuditEventStore) Count(ctx context.Context, f AuditFilter) (int64, error) {
	const op = "audit.Count"
	where, args := f.where()
	var n int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`+where, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store/%s: %w", op, err)
	}
	return n, nil
}
