// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// Scenario mirrors the scenarios table row.
type Scenario struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Description       string    `json:"description"`
	MitreTechniqueIDs []string  `json:"mitre_technique_ids"`
	Tags              []string  `json:"tags"`
	Severity          string    `json:"severity"`
	TimeoutSeconds    int       `json:"timeout_seconds"`
	YAMLContent       string    `json:"yaml_content"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Environment mirrors the environments table row.
type Environment struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	TargetURL string    `json:"target_url"`
	NetworkID string    `json:"network_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ScenarioRun mirrors the scenario_runs table row.
type ScenarioRun struct {
	ID                 string          `json:"id"`
	ScenarioID         string          `json:"scenario_id"`
	EnvironmentID      string          `json:"environment_id"`
	Status             string          `json:"status"`
	StartedAt          *time.Time      `json:"started_at,omitempty"`
	FinishedAt         *time.Time      `json:"finished_at,omitempty"`
	AttackEvents       json.RawMessage `json:"attack_events"`
	DetectionEvents    json.RawMessage `json:"detection_events"`
	DetectionLatencyMs *int            `json:"detection_latency_ms,omitempty"`
	Detected           *bool           `json:"detected,omitempty"`
	Notes              string          `json:"notes"`
}

// MitreCoverage mirrors the mitre_coverage table row.
type MitreCoverage struct {
	TechniqueID    string     `json:"technique_id"`
	TechniqueName  string     `json:"technique_name"`
	Tactic         string     `json:"tactic"`
	ScenarioCount  int        `json:"scenario_count"`
	LastDetectedAt *time.Time `json:"last_detected_at,omitempty"`
	DetectionRate  float64    `json:"detection_rate"`
}

// ---------------------------------------------------------------------------
// Scenario queries
// ---------------------------------------------------------------------------

// InsertScenario inserts a new scenario row and returns the generated UUID.
func InsertScenario(ctx context.Context, q *pgxpool.Pool, s *Scenario) (string, error) {
	const sql = `
		INSERT INTO scenarios
			(name, description, mitre_technique_ids, tags, severity, timeout_seconds, yaml_content)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`

	var id string
	err := q.QueryRow(ctx, sql,
		s.Name,
		s.Description,
		s.MitreTechniqueIDs,
		s.Tags,
		s.Severity,
		s.TimeoutSeconds,
		s.YAMLContent,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("db: insert scenario: %w", err)
	}
	return id, nil
}

// GetScenario fetches a single scenario by UUID.
func GetScenario(ctx context.Context, q *pgxpool.Pool, id string) (*Scenario, error) {
	const sql = `
		SELECT id, name, description, mitre_technique_ids, tags, severity,
		       timeout_seconds, yaml_content, created_at, updated_at
		FROM scenarios
		WHERE id = $1`

	s := &Scenario{}
	err := q.QueryRow(ctx, sql, id).Scan(
		&s.ID, &s.Name, &s.Description, &s.MitreTechniqueIDs, &s.Tags,
		&s.Severity, &s.TimeoutSeconds, &s.YAMLContent, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("db: get scenario: %w", err)
	}
	return s, nil
}

// ListScenarios returns all scenarios ordered by creation time descending.
func ListScenarios(ctx context.Context, q *pgxpool.Pool) ([]*Scenario, error) {
	const sql = `
		SELECT id, name, description, mitre_technique_ids, tags, severity,
		       timeout_seconds, yaml_content, created_at, updated_at
		FROM scenarios
		ORDER BY created_at DESC`

	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("db: list scenarios: %w", err)
	}
	defer rows.Close()

	var list []*Scenario
	for rows.Next() {
		s := &Scenario{}
		if err := rows.Scan(
			&s.ID, &s.Name, &s.Description, &s.MitreTechniqueIDs, &s.Tags,
			&s.Severity, &s.TimeoutSeconds, &s.YAMLContent, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("db: list scenarios scan: %w", err)
		}
		list = append(list, s)
	}
	return list, rows.Err()
}

// ---------------------------------------------------------------------------
// Environment queries
// ---------------------------------------------------------------------------

// InsertEnvironment inserts a new environment row and returns the generated UUID.
func InsertEnvironment(ctx context.Context, q *pgxpool.Pool, e *Environment) (string, error) {
	const sql = `
		INSERT INTO environments
			(name, kind, target_url, network_id, status)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`

	var id string
	err := q.QueryRow(ctx, sql,
		e.Name, e.Kind, e.TargetURL, e.NetworkID, e.Status,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("db: insert environment: %w", err)
	}
	return id, nil
}

// GetEnvironment fetches a single environment by UUID.
func GetEnvironment(ctx context.Context, q *pgxpool.Pool, id string) (*Environment, error) {
	const sql = `
		SELECT id, name, kind, target_url, network_id, status, created_at, updated_at
		FROM environments
		WHERE id = $1`

	e := &Environment{}
	err := q.QueryRow(ctx, sql, id).Scan(
		&e.ID, &e.Name, &e.Kind, &e.TargetURL, &e.NetworkID,
		&e.Status, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("db: get environment: %w", err)
	}
	return e, nil
}

// ListEnvironments returns all environments ordered by name.
func ListEnvironments(ctx context.Context, q *pgxpool.Pool) ([]*Environment, error) {
	const sql = `
		SELECT id, name, kind, target_url, network_id, status, created_at, updated_at
		FROM environments
		ORDER BY name`

	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("db: list environments: %w", err)
	}
	defer rows.Close()

	var list []*Environment
	for rows.Next() {
		e := &Environment{}
		if err := rows.Scan(
			&e.ID, &e.Name, &e.Kind, &e.TargetURL, &e.NetworkID,
			&e.Status, &e.CreatedAt, &e.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("db: list environments scan: %w", err)
		}
		list = append(list, e)
	}
	return list, rows.Err()
}

// ---------------------------------------------------------------------------
// ScenarioRun queries
// ---------------------------------------------------------------------------

// InsertRun creates a new scenario_runs row with status=pending.
func InsertRun(ctx context.Context, q *pgxpool.Pool, r *ScenarioRun) (string, error) {
	const sql = `
		INSERT INTO scenario_runs
			(scenario_id, environment_id, status)
		VALUES ($1, $2, $3)
		RETURNING id`

	var id string
	err := q.QueryRow(ctx, sql, r.ScenarioID, r.EnvironmentID, r.Status).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("db: insert run: %w", err)
	}
	return id, nil
}

// UpdateRunStatus updates a run's mutable fields after execution.
//
// attack_events/detection_events are NOT NULL jsonb columns (DEFAULT '[]'),
// but that default only applies on INSERT — a caller that updates just the
// status (e.g. the initial "mark running" transition, before any events
// exist yet) leaves AttackEvents/DetectionEvents as a nil json.RawMessage,
// which pgx sends as SQL NULL and the column rejects. Default both to an
// empty JSON array here so a partial status update never fails on account
// of fields it wasn't trying to change.
func UpdateRunStatus(ctx context.Context, q *pgxpool.Pool, r *ScenarioRun) error {
	const sql = `
		UPDATE scenario_runs
		SET status               = $1,
		    started_at           = $2,
		    finished_at          = $3,
		    attack_events        = $4,
		    detection_events     = $5,
		    detection_latency_ms = $6,
		    detected             = $7,
		    notes                = $8
		WHERE id = $9`

	attackEvents := r.AttackEvents
	if attackEvents == nil {
		attackEvents = json.RawMessage("[]")
	}
	detectionEvents := r.DetectionEvents
	if detectionEvents == nil {
		detectionEvents = json.RawMessage("[]")
	}

	_, err := q.Exec(ctx, sql,
		r.Status,
		r.StartedAt,
		r.FinishedAt,
		attackEvents,
		detectionEvents,
		r.DetectionLatencyMs,
		r.Detected,
		r.Notes,
		r.ID,
	)
	if err != nil {
		return fmt.Errorf("db: update run status: %w", err)
	}
	return nil
}

// GetRun fetches a single scenario_runs row by UUID.
func GetRun(ctx context.Context, q *pgxpool.Pool, id string) (*ScenarioRun, error) {
	const sql = `
		SELECT id, scenario_id, environment_id, status,
		       started_at, finished_at, attack_events, detection_events,
		       detection_latency_ms, detected, COALESCE(notes, '')
		FROM scenario_runs
		WHERE id = $1`

	r := &ScenarioRun{}
	err := q.QueryRow(ctx, sql, id).Scan(
		&r.ID, &r.ScenarioID, &r.EnvironmentID, &r.Status,
		&r.StartedAt, &r.FinishedAt, &r.AttackEvents, &r.DetectionEvents,
		&r.DetectionLatencyMs, &r.Detected, &r.Notes,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("db: get run: %w", err)
	}
	return r, nil
}

// ListRuns returns all runs ordered by started_at descending.
func ListRuns(ctx context.Context, q *pgxpool.Pool) ([]*ScenarioRun, error) {
	const sql = `
		SELECT id, scenario_id, environment_id, status,
		       started_at, finished_at, attack_events, detection_events,
		       detection_latency_ms, detected, COALESCE(notes, '')
		FROM scenario_runs
		ORDER BY started_at DESC NULLS LAST`

	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("db: list runs: %w", err)
	}
	defer rows.Close()

	var list []*ScenarioRun
	for rows.Next() {
		r := &ScenarioRun{}
		if err := rows.Scan(
			&r.ID, &r.ScenarioID, &r.EnvironmentID, &r.Status,
			&r.StartedAt, &r.FinishedAt, &r.AttackEvents, &r.DetectionEvents,
			&r.DetectionLatencyMs, &r.Detected, &r.Notes,
		); err != nil {
			return nil, fmt.Errorf("db: list runs scan: %w", err)
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

// ---------------------------------------------------------------------------
// MitreCoverage queries
// ---------------------------------------------------------------------------

// UpsertCoverage inserts or updates a mitre_coverage row. On conflict it
// increments scenario_count and updates detection statistics.
func UpsertCoverage(ctx context.Context, q *pgxpool.Pool, c *MitreCoverage) error {
	const sql = `
		INSERT INTO mitre_coverage
			(technique_id, technique_name, tactic, scenario_count, last_detected_at, detection_rate)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (technique_id) DO UPDATE
		SET technique_name   = EXCLUDED.technique_name,
		    tactic           = EXCLUDED.tactic,
		    scenario_count   = mitre_coverage.scenario_count + 1,
		    last_detected_at = GREATEST(mitre_coverage.last_detected_at, EXCLUDED.last_detected_at),
		    detection_rate   = EXCLUDED.detection_rate`

	_, err := q.Exec(ctx, sql,
		c.TechniqueID,
		c.TechniqueName,
		c.Tactic,
		c.ScenarioCount,
		c.LastDetectedAt,
		c.DetectionRate,
	)
	if err != nil {
		return fmt.Errorf("db: upsert coverage: %w", err)
	}
	return nil
}

// ListCoverage returns all mitre_coverage rows ordered by technique_id.
func ListCoverage(ctx context.Context, q *pgxpool.Pool) ([]*MitreCoverage, error) {
	const sql = `
		SELECT technique_id, technique_name, tactic,
		       scenario_count, last_detected_at, detection_rate
		FROM mitre_coverage
		ORDER BY technique_id`

	rows, err := q.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("db: list coverage: %w", err)
	}
	defer rows.Close()

	var list []*MitreCoverage
	for rows.Next() {
		c := &MitreCoverage{}
		if err := rows.Scan(
			&c.TechniqueID, &c.TechniqueName, &c.Tactic,
			&c.ScenarioCount, &c.LastDetectedAt, &c.DetectionRate,
		); err != nil {
			return nil, fmt.Errorf("db: list coverage scan: %w", err)
		}
		list = append(list, c)
	}
	return list, rows.Err()
}
