package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/opensecstack/vertguard/internal/audit"
)

// SaveAuditEvent inserts one audit row. Mutates e.ID/e.Timestamp only
// if unset — caller-supplied values win for replay/import paths.
func (d *DB) SaveAuditEvent(ctx context.Context, e *audit.Event) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}

	// nil metadata becomes SQL NULL, not "null" literal — keeps queries
	// like `metadata @> ...` honest.
	var meta any
	if len(e.Metadata) > 0 {
		meta = []byte(e.Metadata)
	}
	var ip any
	if e.RemoteIP != "" {
		ip = e.RemoteIP
	}

	_, err := d.Pool.Exec(ctx, `
		INSERT INTO audit_events (
			id, ts, actor, role, action, target_type, target_id,
			outcome, status_code, request_id, remote_ip, metadata
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		e.ID, e.Timestamp, e.Actor, e.Role, e.Action,
		nullIfEmpty(e.TargetType), nullIfEmpty(e.TargetID),
		e.Outcome, e.StatusCode,
		nullIfEmpty(e.RequestID), ip, meta,
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// ListAuditEvents returns rows newer-than-or-equal-to the cursor, newest
// first. sinceID is a UUID cursor — empty means "from the top".
func (d *DB) ListAuditEvents(ctx context.Context, limit int, sinceID string) ([]audit.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	// Cursor pagination on (ts, id): rows strictly older than the
	// cursor's ts, or same ts with smaller id. Avoids OFFSET.
	q := `
		SELECT id, ts, COALESCE(actor,''), COALESCE(role,''), action,
		       COALESCE(target_type,''), COALESCE(target_id,''),
		       outcome, COALESCE(status_code,0),
		       COALESCE(request_id,''), COALESCE(host(remote_ip),''),
		       COALESCE(metadata,'null'::jsonb)
		FROM audit_events`
	args := []any{}
	if sinceID != "" {
		cur, err := uuid.Parse(sinceID)
		if err != nil {
			return nil, fmt.Errorf("parse cursor: %w", err)
		}
		q += ` WHERE (ts, id) < (SELECT ts, id FROM audit_events WHERE id = $1)`
		args = append(args, cur)
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT $` + fmt.Sprintf("%d", len(args)+1)
	args = append(args, limit)

	rows, err := d.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	out := make([]audit.Event, 0, limit)
	for rows.Next() {
		var e audit.Event
		var meta []byte
		if err := rows.Scan(
			&e.ID, &e.Timestamp, &e.Actor, &e.Role, &e.Action,
			&e.TargetType, &e.TargetID, &e.Outcome, &e.StatusCode,
			&e.RequestID, &e.RemoteIP, &meta,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		if len(meta) > 0 && string(meta) != "null" {
			e.Metadata = meta
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
