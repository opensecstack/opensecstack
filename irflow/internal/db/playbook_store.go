package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/opensecstack/irflow/internal/playbook"
)

// PGPlaybookStore implements playbook.Store against PostgreSQL.
// It shares a connection pool with PGStore but keeps a distinct type so the
// incident and playbook domains remain independent.
type PGPlaybookStore struct {
	pool querier
}

// NewPGPlaybookStore creates a new PostgreSQL-backed playbook store.
func NewPGPlaybookStore(pool *pgxpool.Pool) *PGPlaybookStore {
	return &PGPlaybookStore{pool: pool}
}

// ---------------------------------------------------------------------------
// Playbook CRUD
// ---------------------------------------------------------------------------

func (s *PGPlaybookStore) Create(ctx context.Context, pb *playbook.Playbook) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	triggerJSON, err := json.Marshal(pb.Trigger)
	if err != nil {
		return fmt.Errorf("marshalling trigger: %w", err)
	}
	stepsJSON, err := json.Marshal(pb.Steps)
	if err != nil {
		return fmt.Errorf("marshalling steps: %w", err)
	}

	query := `
		INSERT INTO playbooks (
			id, name, description, version, status, trigger, steps,
			created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err = s.pool.Exec(ctx, query,
		pb.ID, pb.Name, pb.Description, pb.Version, pb.Status,
		triggerJSON, stepsJSON, pb.CreatedBy, pb.CreatedAt, pb.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting playbook: %w", err)
	}
	return nil
}

func (s *PGPlaybookStore) Get(ctx context.Context, id string) (*playbook.Playbook, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := `
		SELECT id, name, description, version, status, trigger, steps,
		       created_by, created_at, updated_at
		FROM playbooks
		WHERE id = $1`

	var (
		pb           playbook.Playbook
		triggerBytes []byte
		stepsBytes   []byte
	)
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&pb.ID, &pb.Name, &pb.Description, &pb.Version, &pb.Status,
		&triggerBytes, &stepsBytes, &pb.CreatedBy, &pb.CreatedAt, &pb.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, playbook.ErrNotFound
		}
		return nil, fmt.Errorf("querying playbook %s: %w", id, err)
	}

	if err := json.Unmarshal(triggerBytes, &pb.Trigger); err != nil {
		return nil, fmt.Errorf("unmarshalling trigger: %w", err)
	}
	if err := json.Unmarshal(stepsBytes, &pb.Steps); err != nil {
		return nil, fmt.Errorf("unmarshalling steps: %w", err)
	}
	return &pb, nil
}

func (s *PGPlaybookStore) List(ctx context.Context, opts playbook.ListOptions) ([]playbook.Playbook, int, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	var conds []string
	var args []interface{}
	argIdx := 1
	if opts.Status != "" {
		conds = append(conds, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, opts.Status)
		argIdx++
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	var total int
	if err := s.pool.QueryRow(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM playbooks %s", where), args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting playbooks: %w", err)
	}

	offset := (opts.Page - 1) * opts.PerPage
	if offset < 0 {
		offset = 0
	}
	query := fmt.Sprintf(`
		SELECT id, name, description, version, status, trigger, steps,
		       created_by, created_at, updated_at
		FROM playbooks %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, argIdx, argIdx+1)
	args = append(args, opts.PerPage, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing playbooks: %w", err)
	}
	defer rows.Close()

	var results []playbook.Playbook
	for rows.Next() {
		var (
			pb           playbook.Playbook
			triggerBytes []byte
			stepsBytes   []byte
		)
		if err := rows.Scan(
			&pb.ID, &pb.Name, &pb.Description, &pb.Version, &pb.Status,
			&triggerBytes, &stepsBytes, &pb.CreatedBy, &pb.CreatedAt, &pb.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning playbook row: %w", err)
		}
		if err := json.Unmarshal(triggerBytes, &pb.Trigger); err != nil {
			return nil, 0, fmt.Errorf("unmarshalling trigger: %w", err)
		}
		if err := json.Unmarshal(stepsBytes, &pb.Steps); err != nil {
			return nil, 0, fmt.Errorf("unmarshalling steps: %w", err)
		}
		results = append(results, pb)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating playbook rows: %w", err)
	}
	if results == nil {
		results = []playbook.Playbook{}
	}
	return results, total, nil
}

func (s *PGPlaybookStore) Update(ctx context.Context, pb *playbook.Playbook) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	pb.UpdatedAt = time.Now().UTC()
	triggerJSON, err := json.Marshal(pb.Trigger)
	if err != nil {
		return fmt.Errorf("marshalling trigger: %w", err)
	}
	stepsJSON, err := json.Marshal(pb.Steps)
	if err != nil {
		return fmt.Errorf("marshalling steps: %w", err)
	}

	query := `
		UPDATE playbooks SET
			name = $2, description = $3, version = $4, status = $5,
			trigger = $6, steps = $7, updated_at = $8
		WHERE id = $1`

	ct, err := s.pool.Exec(ctx, query,
		pb.ID, pb.Name, pb.Description, pb.Version, pb.Status,
		triggerJSON, stepsJSON, pb.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("updating playbook %s: %w", pb.ID, err)
	}
	if ct.RowsAffected() == 0 {
		return playbook.ErrNotFound
	}
	return nil
}

func (s *PGPlaybookStore) Delete(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	ct, err := s.pool.Exec(ctx, "DELETE FROM playbooks WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("deleting playbook %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return playbook.ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------------------
// Execution persistence
// ---------------------------------------------------------------------------

func (s *PGPlaybookStore) CreateExecution(ctx context.Context, exec *playbook.Execution) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	resultsJSON, err := json.Marshal(exec.StepResults)
	if err != nil {
		return fmt.Errorf("marshalling step results: %w", err)
	}

	query := `
		INSERT INTO playbook_executions (
			id, playbook_id, incident_id, status, current_step,
			step_results, error, started_at, completed_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err = s.pool.Exec(ctx, query,
		exec.ID, exec.PlaybookID, exec.IncidentID, exec.Status,
		exec.CurrentStep, resultsJSON, "", exec.StartedAt, exec.CompletedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting execution: %w", err)
	}
	return nil
}

func (s *PGPlaybookStore) GetExecution(ctx context.Context, id string) (*playbook.Execution, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := `
		SELECT id, playbook_id, incident_id, status, current_step,
		       step_results, error, started_at, completed_at
		FROM playbook_executions
		WHERE id = $1`

	var (
		exec         playbook.Execution
		resultsBytes []byte
		errText      string
	)
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&exec.ID, &exec.PlaybookID, &exec.IncidentID, &exec.Status,
		&exec.CurrentStep, &resultsBytes, &errText,
		&exec.StartedAt, &exec.CompletedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, playbook.ErrNotFound
		}
		return nil, fmt.Errorf("querying execution %s: %w", id, err)
	}
	exec.Error = errText
	if len(resultsBytes) > 0 {
		if err := json.Unmarshal(resultsBytes, &exec.StepResults); err != nil {
			return nil, fmt.Errorf("unmarshalling step results: %w", err)
		}
	}
	return &exec, nil
}

func (s *PGPlaybookStore) ListExecutions(ctx context.Context, playbookID string) ([]playbook.Execution, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	query := `
		SELECT id, playbook_id, incident_id, status, current_step,
		       step_results, error, started_at, completed_at
		FROM playbook_executions
		WHERE playbook_id = $1
		ORDER BY started_at DESC`

	rows, err := s.pool.Query(ctx, query, playbookID)
	if err != nil {
		return nil, fmt.Errorf("listing executions: %w", err)
	}
	defer rows.Close()

	var results []playbook.Execution
	for rows.Next() {
		var (
			exec         playbook.Execution
			resultsBytes []byte
			errText      string
		)
		if err := rows.Scan(
			&exec.ID, &exec.PlaybookID, &exec.IncidentID, &exec.Status,
			&exec.CurrentStep, &resultsBytes, &errText,
			&exec.StartedAt, &exec.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning execution row: %w", err)
		}
		exec.Error = errText
		if len(resultsBytes) > 0 {
			if err := json.Unmarshal(resultsBytes, &exec.StepResults); err != nil {
				return nil, fmt.Errorf("unmarshalling step results: %w", err)
			}
		}
		results = append(results, exec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating execution rows: %w", err)
	}
	if results == nil {
		results = []playbook.Execution{}
	}
	return results, nil
}

func (s *PGPlaybookStore) UpdateExecution(ctx context.Context, exec *playbook.Execution) error {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	resultsJSON, err := json.Marshal(exec.StepResults)
	if err != nil {
		return fmt.Errorf("marshalling step results: %w", err)
	}

	query := `
		UPDATE playbook_executions SET
			status = $2, current_step = $3, step_results = $4,
			error = $5, completed_at = $6
		WHERE id = $1`

	ct, err := s.pool.Exec(ctx, query,
		exec.ID, exec.Status, exec.CurrentStep,
		resultsJSON, exec.Error, exec.CompletedAt,
	)
	if err != nil {
		return fmt.Errorf("updating execution %s: %w", exec.ID, err)
	}
	if ct.RowsAffected() == 0 {
		return playbook.ErrNotFound
	}
	return nil
}
