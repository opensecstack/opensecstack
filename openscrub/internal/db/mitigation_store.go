package db

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Mitigation is one row of the mitigations table — one observed
// drop / ratelimit window for (rule, src_ip).
//
// RuleID is nullable since migration 0002 (FK is ON DELETE SET NULL):
// the row survives rule deletion so CITADEL evidence is never lost.
// Callers reach the original rule via the snapshot fields RuleCIDR /
// RuleType / RuleSource captured at insert time.
type Mitigation struct {
	ID             uuid.UUID
	RuleID         uuid.NullUUID
	RuleCIDR       string
	RuleType       string
	RuleSource     string
	StartedAt      time.Time
	EndedAt        *time.Time
	PacketsDropped int64
	BytesDropped   int64
	SrcIP          *netip.Addr
	Emitted        bool
	State          string // 'pending' | 'sent' | 'failed'
	Attempts       int
	LastError      string
	SentAt         *time.Time
	// StartPacketsDropped / StartBytesDropped capture the *global*
	// dataplane counters at the instant this mitigation row was inserted.
	// The watcher emits (end - start) at finalize time as a best-effort
	// per-rule attribution. See migration 0003 for the v1.1 successor
	// (per-rule PERCPU_HASH counter map).
	StartPacketsDropped int64
	StartBytesDropped   int64
}

// ErrMitigationNotFound is returned by Get when no row matches.
var ErrMitigationNotFound = errors.New("mitigation not found")

// MitigationStore persists Mitigation rows.
type MitigationStore struct {
	pool *pgxpool.Pool
}

// NewMitigationStore wraps a pool.
func NewMitigationStore(pool *pgxpool.Pool) *MitigationStore {
	return &MitigationStore{pool: pool}
}

// Insert writes a new in-progress mitigation (ended_at = NULL). The
// rule snapshot (cidr/type/source) is captured here so the row can
// outlive the parent rule.
func (s *MitigationStore) Insert(ctx context.Context, m Mitigation) (Mitigation, error) {
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	if m.StartedAt.IsZero() {
		m.StartedAt = time.Now().UTC()
	}
	if m.State == "" {
		m.State = "pending"
	}
	const q = `INSERT INTO mitigations
	    (id, rule_id, rule_cidr, rule_type, rule_source,
	     started_at, ended_at, packets_dropped, bytes_dropped, src_ip,
	     emitted, state, attempts, start_packets_dropped, start_bytes_dropped)
	    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	_, err := s.pool.Exec(ctx, q,
		m.ID, nullableUUID(m.RuleID),
		nullableText(m.RuleCIDR), nullableText(m.RuleType), nullableText(m.RuleSource),
		m.StartedAt, m.EndedAt,
		m.PacketsDropped, m.BytesDropped, m.SrcIP,
		m.Emitted, m.State, m.Attempts,
		m.StartPacketsDropped, m.StartBytesDropped)
	if err != nil {
		return Mitigation{}, fmt.Errorf("insert mitigation: %w", err)
	}
	return m, nil
}

// Close marks a mitigation as ended and updates the counters.
func (s *MitigationStore) Close(ctx context.Context, id uuid.UUID, endedAt time.Time, packets, bytes int64) error {
	const q = `UPDATE mitigations
	           SET ended_at = $2, packets_dropped = $3, bytes_dropped = $4
	           WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, id, endedAt, packets, bytes)
	return err
}

// FinalizeForRule closes any *open* mitigation row (ended_at IS NULL) for
// the given rule by setting ended_at and writing the (end - start) delta
// into packets_dropped / bytes_dropped. Negative deltas are clamped to
// zero so a counter rollover (loader restart between start and end) does
// not produce a nonsense negative window. Idempotent: a no-op if no row
// is open.
func (s *MitigationStore) FinalizeForRule(ctx context.Context, ruleID uuid.UUID, endedAt time.Time, endPackets, endBytes int64) error {
	const q = `UPDATE mitigations
	           SET ended_at = $2,
	               packets_dropped = GREATEST(0, $3 - start_packets_dropped),
	               bytes_dropped   = GREATEST(0, $4 - start_bytes_dropped)
	           WHERE rule_id = $1 AND ended_at IS NULL`
	_, err := s.pool.Exec(ctx, q, ruleID, endedAt, endPackets, endBytes)
	return err
}

// OpenRuleIDs returns the set of rule_ids that currently have an open
// mitigation row (ended_at IS NULL). Used at startup so the lifecycle
// can avoid double-inserting after a process restart.
func (s *MitigationStore) OpenRuleIDs(ctx context.Context) (map[uuid.UUID]struct{}, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT rule_id FROM mitigations WHERE ended_at IS NULL AND rule_id IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[uuid.UUID]struct{})
	for rows.Next() {
		var id pgtype.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if id.Valid {
			out[uuid.UUID(id.Bytes)] = struct{}{}
		}
	}
	return out, rows.Err()
}

// MarkEmitted is the legacy entry point retained for the v1.0.x
// compatibility window. Routes to MarkSent so old callers / tests
// continue to work — `emitted=true` is preserved as a derived signal
// for the wire view.
//
// Deprecated: scheduled for removal in v1.1.0. The boolean
// `mitigations.emitted` column will be dropped in migration 0003 and
// the state machine column (`state IN ('pending','sent','failed')`)
// becomes authoritative. New callers MUST use MarkSent / MarkFailed
// directly. See ROADMAP.md "v1.1.0 — drop emitted-bool dual-write".
func (s *MitigationStore) MarkEmitted(ctx context.Context, id uuid.UUID) error {
	return s.MarkSent(ctx, id)
}

// MarkSending records that an emit is in flight. Increments attempts
// and binds the row to the in-flight CITADEL envelope id (used by
// LookupByEventID after a watcher restart).
func (s *MitigationStore) MarkSending(ctx context.Context, id uuid.UUID, eventID string) error {
	const q = `UPDATE mitigations
	           SET attempts = attempts + 1,
	               state = CASE WHEN state = 'failed' THEN 'pending' ELSE state END,
	               last_error = $2
	           WHERE id = $1`
	binding := ""
	if eventID != "" {
		binding = "in_flight:" + eventID
	}
	if _, err := s.pool.Exec(ctx, q, id, nullableText(binding)); err != nil {
		return fmt.Errorf("mark sending: %w", err)
	}
	return nil
}

// MarkSent flips the row to durable state on confirmed CITADEL 2xx.
//
// The dual-write on `emitted` is intentional for the v1.0.x window:
// it keeps the legacy boolean signal in sync with the state-machine
// column so dashboards / reports that haven't migrated yet still
// observe the right value. Migration 0003 (planned for v1.1.0) drops
// the boolean and this UPDATE collapses to `state='sent', sent_at=...`.
func (s *MitigationStore) MarkSent(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE mitigations
	           SET emitted = TRUE, state = 'sent', sent_at = now(), last_error = NULL
	           WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, id)
	return err
}

// MarkFailed records a terminal retry-exhausted / dropped outcome.
func (s *MitigationStore) MarkFailed(ctx context.Context, id uuid.UUID, lastError string) error {
	const q = `UPDATE mitigations
	           SET state = 'failed', last_error = $2
	           WHERE id = $1`
	_, err := s.pool.Exec(ctx, q, id, lastError)
	return err
}

// LookupByEventID resolves a CITADEL envelope id back to the
// originating mitigation row. Used by the watcher's confirmation
// drainer after a process restart, when the in-memory map is empty.
// Returns uuid.Nil when no row matches — confirmation belongs to a
// rule_change event or a row that has since been cleared.
func (s *MitigationStore) LookupByEventID(ctx context.Context, eventID string) (uuid.UUID, error) {
	if eventID == "" {
		return uuid.Nil, nil
	}
	var id uuid.UUID
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM mitigations WHERE last_error = $1 AND state = 'pending' LIMIT 1`,
		"in_flight:"+eventID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// PendingForEmit returns mitigations that have ended, lasted at least
// minDuration, and are still in the 'pending' state.
func (s *MitigationStore) PendingForEmit(ctx context.Context, minDuration time.Duration, limit int) ([]Mitigation, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	// Build the interval in SQL via make_interval rather than passing
	// "<n> seconds" via fmt.Sprintf — the typed integer round-trip
	// removes a footgun (literal text interpolation) and avoids the
	// ::interval cast.
	//
	// Exclude rows already in flight to a CITADEL POST: MarkSending
	// stores the envelope id as last_error="in_flight:<uuid>". Without
	// this guard a watcher restart between MarkSending and the
	// confirmation drainer would re-select the row, mint a NEW envelope
	// id (since emitChange re-serialises the body), and CITADEL would
	// receive two events for one mitigation — dedup at CITADEL is by
	// envelope id, so changing it defeats idempotency.
	const q = `SELECT id, rule_id, rule_cidr, rule_type, rule_source,
	                  started_at, ended_at, packets_dropped, bytes_dropped, src_ip,
	                  emitted, state, attempts, last_error, sent_at,
	                  start_packets_dropped, start_bytes_dropped
	           FROM mitigations
	           WHERE state = 'pending'
	             AND ended_at IS NOT NULL
	             AND ended_at - started_at >= make_interval(secs => $1)
	             AND (last_error IS NULL OR last_error NOT LIKE 'in_flight:%')
	           ORDER BY ended_at ASC
	           LIMIT $2`
	rows, err := s.pool.Query(ctx, q, int(minDuration.Seconds()), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Mitigation
	for rows.Next() {
		m, err := scanMitigation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// FailedCount returns the number of mitigations stuck in state='failed'.
func (s *MitigationStore) FailedCount(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mitigations WHERE state = 'failed'`).Scan(&n)
	return n, err
}

// List returns mitigations ordered by started_at DESC. When `since` is
// non-zero, only rows with started_at >= since are returned. When
// `ruleID` is non-zero, only rows for that rule are returned.
func (s *MitigationStore) List(ctx context.Context, since time.Time, ruleID uuid.UUID, limit int) ([]Mitigation, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id, rule_id, rule_cidr, rule_type, rule_source,
	             started_at, ended_at, packets_dropped, bytes_dropped, src_ip,
	             emitted, state, attempts, last_error, sent_at,
	             start_packets_dropped, start_bytes_dropped
	      FROM mitigations
	      WHERE ($1::timestamptz IS NULL OR started_at >= $1)
	        AND ($2::uuid IS NULL OR rule_id = $2)
	      ORDER BY started_at DESC
	      LIMIT $3`
	var (
		sinceArg any = nil
		ruleArg  any = nil
	)
	if !since.IsZero() {
		sinceArg = since
	}
	if ruleID != uuid.Nil {
		ruleArg = ruleID
	}
	rows, err := s.pool.Query(ctx, q, sinceArg, ruleArg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Mitigation
	for rows.Next() {
		m, err := scanMitigation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Get returns one mitigation by id.
func (s *MitigationStore) Get(ctx context.Context, id uuid.UUID) (Mitigation, error) {
	const q = `SELECT id, rule_id, rule_cidr, rule_type, rule_source,
	                  started_at, ended_at, packets_dropped, bytes_dropped, src_ip,
	                  emitted, state, attempts, last_error, sent_at,
	                  start_packets_dropped, start_bytes_dropped
	           FROM mitigations WHERE id = $1`
	row := s.pool.QueryRow(ctx, q, id)
	m, err := scanMitigation(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Mitigation{}, ErrMitigationNotFound
	}
	return m, err
}

// scanMitigation decodes one row from either pgx.Rows or pgx.Row.
func scanMitigation(r pgx.Row) (Mitigation, error) {
	var (
		m        Mitigation
		ruleID   pgtype.UUID
		ruleCIDR *netip.Prefix
		ruleType *string
		ruleSrc  *string
		ended    *time.Time
		src      *netip.Addr
		state    *string
		lastErr  *string
		sentAt   *time.Time
	)
	if err := r.Scan(&m.ID, &ruleID, &ruleCIDR, &ruleType, &ruleSrc,
		&m.StartedAt, &ended,
		&m.PacketsDropped, &m.BytesDropped, &src,
		&m.Emitted, &state, &m.Attempts, &lastErr, &sentAt,
		&m.StartPacketsDropped, &m.StartBytesDropped); err != nil {
		return Mitigation{}, err
	}
	if ruleID.Valid {
		m.RuleID = uuid.NullUUID{UUID: uuid.UUID(ruleID.Bytes), Valid: true}
	}
	if ruleCIDR != nil {
		m.RuleCIDR = ruleCIDR.String()
	}
	if ruleType != nil {
		m.RuleType = *ruleType
	}
	if ruleSrc != nil {
		m.RuleSource = *ruleSrc
	}
	m.EndedAt = ended
	m.SrcIP = src
	if state != nil {
		m.State = *state
	}
	if lastErr != nil {
		m.LastError = *lastErr
	}
	m.SentAt = sentAt
	return m, nil
}

func nullableUUID(u uuid.NullUUID) any {
	if !u.Valid {
		return nil
	}
	return u.UUID
}

func nullableText(s string) any {
	if s == "" {
		return nil
	}
	return s
}
