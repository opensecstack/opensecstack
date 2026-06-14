// Package audit provides immutable audit logging for VertGuard.
//
// Every state-changing API call emits an Event to one or more sinks.
// Sinks are best-effort: a sink failure is logged but never blocks the
// originating request, so a downed Postgres can't cause a 5xx.
package audit

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Outcome values are the only legal Event.Outcome strings.
const (
	OutcomeSuccess = "success"
	OutcomeDenied  = "denied"
	OutcomeError   = "error"
)

// Event is the canonical audit record. Mirrors the audit_events table
// layout 1:1 so inserts are mechanical.
type Event struct {
	ID         uuid.UUID       `json:"id"`
	Timestamp  time.Time       `json:"ts"`
	Actor      string          `json:"actor"`
	Role       string          `json:"role"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type,omitempty"`
	TargetID   string          `json:"target_id,omitempty"`
	Outcome    string          `json:"outcome"`
	StatusCode int             `json:"status_code"`
	RequestID  string          `json:"request_id,omitempty"`
	RemoteIP   string          `json:"remote_ip,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// Sink is anything that durably records audit events.
type Sink interface {
	Record(ctx context.Context, e Event) error
}

// LoggerSink writes events as a JSONL stream via zerolog with audit:true
// so log shippers can split it from the normal request log stream.
type LoggerSink struct {
	logger *zerolog.Logger
}

// NewLoggerSink wraps a zerolog logger as a Sink.
func NewLoggerSink(l *zerolog.Logger) *LoggerSink { return &LoggerSink{logger: l} }

// Record emits one structured event line.
func (s *LoggerSink) Record(_ context.Context, e Event) error {
	if s == nil || s.logger == nil {
		return nil
	}
	ev := s.logger.Info().
		Bool("audit", true).
		Str("event_id", e.ID.String()).
		Time("ts", e.Timestamp).
		Str("actor", e.Actor).
		Str("role", e.Role).
		Str("action", e.Action).
		Str("outcome", e.Outcome).
		Int("status", e.StatusCode).
		Str("request_id", e.RequestID).
		Str("remote_ip", e.RemoteIP)
	if e.TargetType != "" {
		ev = ev.Str("target_type", e.TargetType)
	}
	if e.TargetID != "" {
		ev = ev.Str("target_id", e.TargetID)
	}
	if len(e.Metadata) > 0 {
		ev = ev.RawJSON("metadata", e.Metadata)
	}
	ev.Msg("audit")
	return nil
}

// DBStore is the narrow surface DBSink needs from internal/db.DB —
// keeps audit decoupled from pgx transitively.
type DBStore interface {
	SaveAuditEvent(ctx context.Context, e *Event) error
}

// DBSink writes events to the audit_events table.
type DBSink struct {
	store DBStore
}

// NewDBSink wraps a DBStore.
func NewDBSink(s DBStore) *DBSink { return &DBSink{store: s} }

// Record persists one event.
func (s *DBSink) Record(ctx context.Context, e Event) error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.SaveAuditEvent(ctx, &e)
}

// MultiSink fans out to N sinks. A failure in one is logged but never
// short-circuits the others — request path must not be blocked by audit.
type MultiSink struct {
	sinks  []Sink
	logger *zerolog.Logger
}

// NewMultiSink composes sinks with best-effort semantics.
func NewMultiSink(logger *zerolog.Logger, sinks ...Sink) *MultiSink {
	out := make([]Sink, 0, len(sinks))
	for _, s := range sinks {
		if s != nil {
			out = append(out, s)
		}
	}
	return &MultiSink{sinks: out, logger: logger}
}

// Record fans out, swallowing errors after logging them.
func (m *MultiSink) Record(ctx context.Context, e Event) error {
	if m == nil {
		return nil
	}
	for _, s := range m.sinks {
		if err := s.Record(ctx, e); err != nil && m.logger != nil {
			m.logger.Warn().
				Err(err).
				Str("event_id", e.ID.String()).
				Msg("audit sink failed")
		}
	}
	return nil
}

// ParseRemoteIP normalises a RemoteAddr / X-Real-IP into a bare IP for
// the INET column. Empty string when unparsable.
func ParseRemoteIP(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String()
	}
	return ""
}
