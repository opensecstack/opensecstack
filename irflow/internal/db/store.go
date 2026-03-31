package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/opensecstack/irflow/internal/incident"
)

// queryTimeout is the default timeout applied to every database operation.
const queryTimeout = 30 * time.Second

// PGStore implements incident.Store using PostgreSQL.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore creates a new PostgreSQL-backed incident store.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

// ---------------------------------------------------------------------------
// Incident CRUD
// ---------------------------------------------------------------------------

// Create inserts a new incident row. It generates a UUID if the ID field is
// empty, and populates created_at / updated_at timestamps.
func (s *PGStore) Create(ctx context.Context, inc *incident.Incident) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	if inc.ID == "" {
		inc.ID = fmt.Sprintf("inc-%d", time.Now().UnixNano())
	}

	now := time.Now().UTC()
	if inc.CreatedAt.IsZero() {
		inc.CreatedAt = now
	}
	inc.UpdatedAt = now

	query := `
		INSERT INTO incidents (
			id, title, description, severity, status, source, source_ref,
			project_id, commander_id, lead_id, root_cause, corrective_action,
			worm_entry_id, nis2_notify_required, nis2_notified_at,
			contained_at, closed_at, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7,
			$8, $9, $10, $11, $12,
			$13, $14, $15,
			$16, $17, $18, $19
		)`

	_, err := s.pool.Exec(ctx, query,
		inc.ID, inc.Title, inc.Description, inc.Severity, inc.Status,
		inc.Source, inc.SourceRef, inc.ProjectID, inc.CommanderID, inc.LeadID,
		inc.RootCause, inc.CorrectiveAction, inc.WORMEntryID,
		inc.NIS2NotifyRequired, inc.NIS2NotifiedAt,
		inc.ContainedAt, inc.ClosedAt, inc.CreatedAt, inc.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting incident: %w", err)
	}

	return nil
}

// Get retrieves a single incident by ID.
func (s *PGStore) Get(ctx context.Context, id string) (*incident.Incident, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := `
		SELECT id, title, description, severity, status, source, source_ref,
		       project_id, commander_id, lead_id, root_cause, corrective_action,
		       worm_entry_id, nis2_notify_required, nis2_notified_at,
		       contained_at, closed_at, created_at, updated_at
		FROM incidents
		WHERE id = $1`

	inc := &incident.Incident{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&inc.ID, &inc.Title, &inc.Description, &inc.Severity, &inc.Status,
		&inc.Source, &inc.SourceRef, &inc.ProjectID, &inc.CommanderID, &inc.LeadID,
		&inc.RootCause, &inc.CorrectiveAction, &inc.WORMEntryID,
		&inc.NIS2NotifyRequired, &inc.NIS2NotifiedAt,
		&inc.ContainedAt, &inc.ClosedAt, &inc.CreatedAt, &inc.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, incident.ErrNotFound
		}
		return nil, fmt.Errorf("querying incident %s: %w", id, err)
	}

	return inc, nil
}

// List retrieves a page of incidents with optional filters.
// It returns the matching incidents and the total count (for pagination).
func (s *PGStore) List(ctx context.Context, opts incident.ListOptions) ([]incident.Incident, int, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	// Build WHERE clause dynamically.
	var conditions []string
	var args []interface{}
	argIdx := 1

	if opts.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, opts.Status)
		argIdx++
	}
	if opts.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, opts.Severity)
		argIdx++
	}
	if opts.Source != "" {
		conditions = append(conditions, fmt.Sprintf("source = $%d", argIdx))
		args = append(args, opts.Source)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching rows.
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM incidents %s", whereClause)
	var totalCount int
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&totalCount); err != nil {
		return nil, 0, fmt.Errorf("counting incidents: %w", err)
	}

	// Fetch the page.
	offset := (opts.Page - 1) * opts.PerPage
	if offset < 0 {
		offset = 0
	}

	dataQuery := fmt.Sprintf(`
		SELECT id, title, description, severity, status, source, source_ref,
		       project_id, commander_id, lead_id, root_cause, corrective_action,
		       worm_entry_id, nis2_notify_required, nis2_notified_at,
		       contained_at, closed_at, created_at, updated_at
		FROM incidents %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, whereClause, argIdx, argIdx+1)

	args = append(args, opts.PerPage, offset)

	rows, err := s.pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing incidents: %w", err)
	}
	defer rows.Close()

	var results []incident.Incident
	for rows.Next() {
		var inc incident.Incident
		if err := rows.Scan(
			&inc.ID, &inc.Title, &inc.Description, &inc.Severity, &inc.Status,
			&inc.Source, &inc.SourceRef, &inc.ProjectID, &inc.CommanderID, &inc.LeadID,
			&inc.RootCause, &inc.CorrectiveAction, &inc.WORMEntryID,
			&inc.NIS2NotifyRequired, &inc.NIS2NotifiedAt,
			&inc.ContainedAt, &inc.ClosedAt, &inc.CreatedAt, &inc.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning incident row: %w", err)
		}
		results = append(results, inc)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating incident rows: %w", err)
	}

	if results == nil {
		results = []incident.Incident{}
	}

	return results, totalCount, nil
}

// Update persists changes to an existing incident, setting updated_at = now().
func (s *PGStore) Update(ctx context.Context, inc *incident.Incident) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	inc.UpdatedAt = time.Now().UTC()

	query := `
		UPDATE incidents SET
			title = $2, description = $3, severity = $4, status = $5,
			source = $6, source_ref = $7, project_id = $8,
			commander_id = $9, lead_id = $10, root_cause = $11,
			corrective_action = $12, worm_entry_id = $13,
			nis2_notify_required = $14, nis2_notified_at = $15,
			contained_at = $16, closed_at = $17, updated_at = $18
		WHERE id = $1`

	ct, err := s.pool.Exec(ctx, query,
		inc.ID, inc.Title, inc.Description, inc.Severity, inc.Status,
		inc.Source, inc.SourceRef, inc.ProjectID,
		inc.CommanderID, inc.LeadID, inc.RootCause,
		inc.CorrectiveAction, inc.WORMEntryID,
		inc.NIS2NotifyRequired, inc.NIS2NotifiedAt,
		inc.ContainedAt, inc.ClosedAt, inc.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("updating incident %s: %w", inc.ID, err)
	}
	if ct.RowsAffected() == 0 {
		return incident.ErrNotFound
	}

	return nil
}

// Delete removes an incident by ID.
func (s *PGStore) Delete(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	ct, err := s.pool.Exec(ctx, "DELETE FROM incidents WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("deleting incident %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return incident.ErrNotFound
	}

	return nil
}

// ---------------------------------------------------------------------------
// Incident actions
// ---------------------------------------------------------------------------

// AddAction inserts a new governed action for an incident.
func (s *PGStore) AddAction(ctx context.Context, action *incident.IncidentAction) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	if action.ID == "" {
		action.ID = fmt.Sprintf("act-%d", time.Now().UnixNano())
	}
	if action.CreatedAt.IsZero() {
		action.CreatedAt = time.Now().UTC()
	}

	// Marshal evidence JSON for storage.
	var evidenceBytes []byte
	if action.Evidence != nil {
		evidenceBytes = []byte(action.Evidence)
	}

	query := `
		INSERT INTO incident_actions (
			id, incident_id, action_type, operator_id, verifier_id,
			description, evidence, marshal_decision, worm_entry_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := s.pool.Exec(ctx, query,
		action.ID, action.IncidentID, action.ActionType,
		action.OperatorID, action.VerifierID,
		action.Description, evidenceBytes,
		action.MarshalDecision, action.WORMEntryID,
		action.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting action: %w", err)
	}

	return nil
}

// ListActions returns all actions for a given incident, ordered by creation time.
func (s *PGStore) ListActions(ctx context.Context, incidentID string) ([]incident.IncidentAction, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := `
		SELECT id, incident_id, action_type, operator_id, verifier_id,
		       description, evidence, marshal_decision, worm_entry_id, created_at
		FROM incident_actions
		WHERE incident_id = $1
		ORDER BY created_at`

	rows, err := s.pool.Query(ctx, query, incidentID)
	if err != nil {
		return nil, fmt.Errorf("listing actions for incident %s: %w", incidentID, err)
	}
	defer rows.Close()

	var actions []incident.IncidentAction
	for rows.Next() {
		var a incident.IncidentAction
		var evidenceBytes []byte
		if err := rows.Scan(
			&a.ID, &a.IncidentID, &a.ActionType, &a.OperatorID, &a.VerifierID,
			&a.Description, &evidenceBytes, &a.MarshalDecision, &a.WORMEntryID,
			&a.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning action row: %w", err)
		}
		if evidenceBytes != nil {
			a.Evidence = json.RawMessage(evidenceBytes)
		}
		actions = append(actions, a)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating action rows: %w", err)
	}

	if actions == nil {
		actions = []incident.IncidentAction{}
	}

	return actions, nil
}

// ---------------------------------------------------------------------------
// IOC Enrichments
// ---------------------------------------------------------------------------

// AddIOC inserts an IOC enrichment record for an incident.
func (s *PGStore) AddIOC(ctx context.Context, ioc *incident.IOCEnrichment) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	if ioc.ID == "" {
		ioc.ID = fmt.Sprintf("ioc-%d", time.Now().UnixNano())
	}
	if ioc.CreatedAt.IsZero() {
		ioc.CreatedAt = time.Now().UTC()
	}

	var stixBytes []byte
	if ioc.STIXBundle != nil {
		stixBytes = []byte(ioc.STIXBundle)
	}

	query := `
		INSERT INTO ioc_enrichments (
			id, incident_id, ioc_type, ioc_value, confidence,
			source, stix_bundle, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := s.pool.Exec(ctx, query,
		ioc.ID, ioc.IncidentID, ioc.IOCType, ioc.IOCValue,
		ioc.Confidence, ioc.Source, stixBytes, ioc.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting IOC: %w", err)
	}

	return nil
}

// ListIOCs returns all IOC enrichments for a given incident.
func (s *PGStore) ListIOCs(ctx context.Context, incidentID string) ([]incident.IOCEnrichment, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := `
		SELECT id, incident_id, ioc_type, ioc_value, confidence,
		       source, stix_bundle, created_at
		FROM ioc_enrichments
		WHERE incident_id = $1
		ORDER BY created_at`

	rows, err := s.pool.Query(ctx, query, incidentID)
	if err != nil {
		return nil, fmt.Errorf("listing IOCs for incident %s: %w", incidentID, err)
	}
	defer rows.Close()

	var iocs []incident.IOCEnrichment
	for rows.Next() {
		var ioc incident.IOCEnrichment
		var stixBytes []byte
		if err := rows.Scan(
			&ioc.ID, &ioc.IncidentID, &ioc.IOCType, &ioc.IOCValue,
			&ioc.Confidence, &ioc.Source, &stixBytes, &ioc.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning IOC row: %w", err)
		}
		if stixBytes != nil {
			ioc.STIXBundle = json.RawMessage(stixBytes)
		}
		iocs = append(iocs, ioc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating IOC rows: %w", err)
	}

	if iocs == nil {
		iocs = []incident.IOCEnrichment{}
	}

	return iocs, nil
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

// GetTimeline returns all timeline entries for a given incident.
func (s *PGStore) GetTimeline(ctx context.Context, incidentID string) ([]incident.TimelineEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := `
		SELECT id, incident_id, entry_type, actor_id, summary,
		       details, created_at
		FROM timeline_entries
		WHERE incident_id = $1
		ORDER BY created_at`

	rows, err := s.pool.Query(ctx, query, incidentID)
	if err != nil {
		return nil, fmt.Errorf("listing timeline for incident %s: %w", incidentID, err)
	}
	defer rows.Close()

	var entries []incident.TimelineEntry
	for rows.Next() {
		var e incident.TimelineEntry
		var detailBytes []byte
		if err := rows.Scan(
			&e.ID, &e.IncidentID, &e.EntryType, &e.ActorID,
			&e.Summary, &detailBytes, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning timeline row: %w", err)
		}
		if detailBytes != nil {
			e.Details = json.RawMessage(detailBytes)
		}
		entries = append(entries, e)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating timeline rows: %w", err)
	}

	if entries == nil {
		entries = []incident.TimelineEntry{}
	}

	return entries, nil
}
