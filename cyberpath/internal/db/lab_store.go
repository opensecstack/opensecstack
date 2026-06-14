// Package db — lab_store manages `lab_definitions` and `lab_sessions`.
// lab_sessions is range-partitioned on started_at; PK is (id, started_at).
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

// LabDefinition mirrors a row in `lab_definitions`. ID is the slug.
type LabDefinition struct {
	ID               string          `json:"id"`
	TrackID          *uuid.UUID      `json:"track_id,omitempty"`
	Runtime          string          `json:"runtime"`
	Image            string          `json:"image"`
	EntryCommand     string          `json:"entry_command"`
	Assets           json.RawMessage `json:"assets"`
	Validation       json.RawMessage `json:"validation"`
	TimeLimitSeconds int             `json:"time_limit_seconds"`
	EgressWhitelist  json.RawMessage `json:"egress_whitelist"`
	SuccessCriteria  string          `json:"success_criteria"`
	Hints            json.RawMessage `json:"hints"`
	Version          int             `json:"version"`
	ContentHash      string          `json:"content_hash"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	DeletedAt        *time.Time      `json:"deleted_at,omitempty"`
}

// LabSession mirrors a row in `lab_sessions`.
type LabSession struct {
	ID           uuid.UUID       `json:"id"`
	LabID        string          `json:"lab_id"`
	UserID       uuid.UUID       `json:"user_id"`
	CohortID     *uuid.UUID      `json:"cohort_id,omitempty"`
	TenantID     uuid.UUID       `json:"tenant_id"`
	Status       string          `json:"status"`
	StartedAt    time.Time       `json:"started_at"`
	EndedAt      *time.Time      `json:"ended_at,omitempty"`
	Runtime      string          `json:"runtime"`
	Result       json.RawMessage `json:"result"`
	AuditLogURL  string          `json:"audit_log_url"`
	AuditHash    string          `json:"audit_hash"`
	OutcomeScore *int            `json:"outcome_score,omitempty"`
	Metadata     json.RawMessage `json:"metadata"`
}

// LabStore wraps a pgx pool for lab definitions + sessions.
type LabStore struct {
	Pool *pgxpool.Pool
}

// NewLabStore wires a LabStore.
func NewLabStore(pool *pgxpool.Pool) *LabStore { return &LabStore{Pool: pool} }

const labDefColumns = `id, track_id, runtime, image, entry_command,
	assets, validation, time_limit_seconds, egress_whitelist,
	success_criteria, hints, version, content_hash,
	created_at, updated_at, deleted_at`

const labSessionColumns = `id, lab_id, user_id, cohort_id, tenant_id, status,
	started_at, ended_at, runtime, result, audit_log_url, audit_hash,
	outcome_score, metadata`

func scanLabDef(row pgx.Row) (*LabDefinition, error) {
	var d LabDefinition
	if err := row.Scan(
		&d.ID, &d.TrackID, &d.Runtime, &d.Image, &d.EntryCommand,
		&d.Assets, &d.Validation, &d.TimeLimitSeconds, &d.EgressWhitelist,
		&d.SuccessCriteria, &d.Hints, &d.Version, &d.ContentHash,
		&d.CreatedAt, &d.UpdatedAt, &d.DeletedAt,
	); err != nil {
		return nil, err
	}
	return &d, nil
}

func scanLabSession(row pgx.Row) (*LabSession, error) {
	var s LabSession
	if err := row.Scan(
		&s.ID, &s.LabID, &s.UserID, &s.CohortID, &s.TenantID, &s.Status,
		&s.StartedAt, &s.EndedAt, &s.Runtime, &s.Result, &s.AuditLogURL, &s.AuditHash,
		&s.OutcomeScore, &s.Metadata,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

// GetDefinition returns a lab definition by slug-id.
func (s *LabStore) GetDefinition(ctx context.Context, id string) (*LabDefinition, error) {
	const op = "lab.GetDefinition"
	row := s.Pool.QueryRow(ctx, `SELECT `+labDefColumns+` FROM lab_definitions WHERE id = $1`, id)
	out, err := scanLabDef(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// ListDefinitionsByTrack returns non-deleted lab defs for a track.
func (s *LabStore) ListDefinitionsByTrack(ctx context.Context, trackID uuid.UUID) ([]LabDefinition, error) {
	const op = "lab.ListDefinitionsByTrack"
	rows, err := s.Pool.Query(ctx, `
		SELECT `+labDefColumns+` FROM lab_definitions
		WHERE track_id = $1 AND deleted_at IS NULL
		ORDER BY id`, trackID)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]LabDefinition, 0, 8)
	for rows.Next() {
		d, err := scanLabDef(rows)
		if err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}

// StartSession inserts a new lab_sessions row in 'starting' state. The
// runtime is copied from the lab definition (it is immutable for the session).
func (s *LabStore) StartSession(ctx context.Context, labID string, userID uuid.UUID, cohortID *uuid.UUID, tenantID uuid.UUID) (*LabSession, error) {
	const op = "lab.StartSession"

	// Lookup runtime from definition; we don't trust the caller for this.
	var runtime string
	if err := s.Pool.QueryRow(ctx, `SELECT runtime FROM lab_definitions WHERE id = $1`, labID).Scan(&runtime); err != nil {
		return nil, fmt.Errorf("store/%s: lookup runtime: %w", op, err)
	}

	row := s.Pool.QueryRow(ctx, `
		INSERT INTO lab_sessions (
			id, lab_id, user_id, cohort_id, tenant_id, status, runtime
		) VALUES ($1, $2, $3, $4, $5, 'starting', $6)
		RETURNING `+labSessionColumns,
		uuid.New(), labID, userID, nullableUUID(cohortID), tenantID, runtime,
	)
	out, err := scanLabSession(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// EndSession finalises a session row. status is one of completed|failed|timeout|cancelled.
// Note: lab_sessions is partitioned on started_at, so the WHERE clause must
// match the partition key column too — we accept the started_at timestamp via
// the existing row, so callers should re-fetch via GetSession if they only
// have the id. To simplify, we update by id alone (the partition router
// handles the lookup, at the cost of scanning all partitions).
func (s *LabStore) EndSession(ctx context.Context, sessionID uuid.UUID, status string, result json.RawMessage, score *int, auditURL, auditHash string) error {
	const op = "lab.EndSession"
	if len(result) == 0 {
		result = []byte("{}")
	}
	_, err := s.Pool.Exec(ctx, `
		UPDATE lab_sessions
		SET status = $2, ended_at = now(), result = $3,
		    outcome_score = $4, audit_log_url = $5, audit_hash = $6
		WHERE id = $1`,
		sessionID, status, []byte(result), nullableInt(score), auditURL, auditHash)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}

// GetSession returns a session by id.
func (s *LabStore) GetSession(ctx context.Context, id uuid.UUID) (*LabSession, error) {
	const op = "lab.GetSession"
	row := s.Pool.QueryRow(ctx, `SELECT `+labSessionColumns+` FROM lab_sessions WHERE id = $1`, id)
	out, err := scanLabSession(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// UpdateMetadata sets the metadata JSON blob for a session.
func (s *LabStore) UpdateMetadata(ctx context.Context, sessionID uuid.UUID, metadata json.RawMessage) error {
	const op = "lab.UpdateMetadata"
	_, err := s.Pool.Exec(ctx,
		`UPDATE lab_sessions SET metadata = $2 WHERE id = $1`,
		sessionID, []byte(metadata),
	)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}

// ListSessionsByUser returns recent sessions for a user, newest first.
func (s *LabStore) ListSessionsByUser(ctx context.Context, userID uuid.UUID) ([]LabSession, error) {
	const op = "lab.ListSessionsByUser"
	rows, err := s.Pool.Query(ctx, `
		SELECT `+labSessionColumns+` FROM lab_sessions
		WHERE user_id = $1
		ORDER BY started_at DESC
		LIMIT 200`, userID)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]LabSession, 0, 16)
	for rows.Next() {
		ls, err := scanLabSession(rows)
		if err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *ls)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}
