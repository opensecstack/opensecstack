// Package db — cohort_store manages the `cohorts` table.
// Instructor-managed learner groups, soft-deleted via deleted_at.
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

// Cohort mirrors a row in the `cohorts` table.
type Cohort struct {
	ID          uuid.UUID       `json:"id"`
	TenantID    uuid.UUID       `json:"tenant_id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	TrackID     *uuid.UUID      `json:"track_id,omitempty"`
	StartDate   *time.Time      `json:"start_date,omitempty"`
	EndDate     *time.Time      `json:"end_date,omitempty"`
	CreatedBy   uuid.UUID       `json:"created_by"`
	Status      string          `json:"status"`
	Metadata    json.RawMessage `json:"metadata"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	DeletedAt   *time.Time      `json:"deleted_at,omitempty"`
}

// CohortStore wraps a pgx pool for `cohorts` reads/writes.
type CohortStore struct {
	Pool *pgxpool.Pool
}

// NewCohortStore wires a CohortStore.
func NewCohortStore(pool *pgxpool.Pool) *CohortStore { return &CohortStore{Pool: pool} }

const cohortColumns = `id, tenant_id, name, description, track_id,
	start_date, end_date, created_by, status, metadata,
	created_at, updated_at, deleted_at`

func scanCohort(row interface {
	Scan(dest ...any) error
}) (*Cohort, error) {
	var c Cohort
	if err := row.Scan(
		&c.ID, &c.TenantID, &c.Name, &c.Description, &c.TrackID,
		&c.StartDate, &c.EndDate, &c.CreatedBy, &c.Status, &c.Metadata,
		&c.CreatedAt, &c.UpdatedAt, &c.DeletedAt,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

// Create inserts a new cohort and returns the persisted row (id+timestamps populated).
func (s *CohortStore) Create(ctx context.Context, c *Cohort) (*Cohort, error) {
	const op = "cohort.Create"
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if len(c.Metadata) == 0 {
		c.Metadata = []byte("{}")
	}
	if c.Status == "" {
		c.Status = "planned"
	}
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO cohorts (
			id, tenant_id, name, description, track_id,
			start_date, end_date, created_by, status, metadata
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING `+cohortColumns,
		c.ID, c.TenantID, c.Name, c.Description, nullableUUID(c.TrackID),
		nullableTime(c.StartDate), nullableTime(c.EndDate), c.CreatedBy, c.Status, c.Metadata,
	)
	out, err := scanCohort(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// Get returns a cohort by id (including soft-deleted rows; callers filter).
func (s *CohortStore) Get(ctx context.Context, id uuid.UUID) (*Cohort, error) {
	const op = "cohort.Get"
	row := s.Pool.QueryRow(ctx, `SELECT `+cohortColumns+` FROM cohorts WHERE id = $1`, id)
	out, err := scanCohort(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// ListByTenant returns non-deleted cohorts for a tenant, optionally filtered by status.
// Pass an empty string for statusFilter to skip the status predicate.
func (s *CohortStore) ListByTenant(ctx context.Context, tenantID uuid.UUID, statusFilter string) ([]Cohort, error) {
	const op = "cohort.ListByTenant"
	q := `SELECT ` + cohortColumns + ` FROM cohorts
	      WHERE tenant_id = $1 AND deleted_at IS NULL`
	args := []any{tenantID}
	if statusFilter != "" {
		q += ` AND status = $2`
		args = append(args, statusFilter)
	}
	q += ` ORDER BY created_at DESC`

	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Cohort, 0, 16)
	for rows.Next() {
		c, err := scanCohort(rows)
		if err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}

// Update overwrites mutable fields. Only the columns relevant to instructor
// edits are touched; tenant_id/created_by are immutable.
func (s *CohortStore) Update(ctx context.Context, c *Cohort) (*Cohort, error) {
	const op = "cohort.Update"
	if len(c.Metadata) == 0 {
		c.Metadata = []byte("{}")
	}
	row := s.Pool.QueryRow(ctx, `
		UPDATE cohorts SET
			name        = $2,
			description = $3,
			track_id    = $4,
			start_date  = $5,
			end_date    = $6,
			status      = $7,
			metadata    = $8,
			updated_at  = now()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING `+cohortColumns,
		c.ID, c.Name, c.Description, nullableUUID(c.TrackID),
		nullableTime(c.StartDate), nullableTime(c.EndDate), c.Status, c.Metadata,
	)
	out, err := scanCohort(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// SoftDelete sets deleted_at = now() on the cohort. Idempotent.
func (s *CohortStore) SoftDelete(ctx context.Context, id uuid.UUID) error {
	const op = "cohort.SoftDelete"
	_, err := s.Pool.Exec(ctx, `
		UPDATE cohorts SET deleted_at = now(), updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}

// LinkTracks inserts rows into the cohort_tracks join table for each
// supplied trackID (uuid) and trackSlug (opaque string). Either slice
// may be empty; both empty makes the call a no-op. Duplicate (cohort,
// track) pairs are silently skipped via ON CONFLICT — replays are safe.
//
// The join table is the schema-of-record for multi-track cohorts (see
// migration 0007). Callers using the join SHOULD leave cohorts.track_id
// NULL on Create so a single lookup pattern resolves all tracks.
func (s *CohortStore) LinkTracks(ctx context.Context, cohortID uuid.UUID, trackIDs []uuid.UUID, trackSlugs []string) error {
	const op = "cohort.LinkTracks"
	if len(trackIDs) == 0 && len(trackSlugs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, tid := range trackIDs {
		t := tid
		batch.Queue(`
			INSERT INTO cohort_tracks (cohort_id, track_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING`, cohortID, t)
	}
	for _, slug := range trackSlugs {
		if slug == "" {
			continue
		}
		batch.Queue(`
			INSERT INTO cohort_tracks (cohort_id, track_slug)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING`, cohortID, slug)
	}
	if batch.Len() == 0 {
		return nil
	}
	br := s.Pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("store/%s: %w", op, err)
		}
	}
	return nil
}

// ListByInstructor returns the cohorts a given user owns (created_by).
func (s *CohortStore) ListByInstructor(ctx context.Context, userID uuid.UUID) ([]Cohort, error) {
	const op = "cohort.ListByInstructor"
	rows, err := s.Pool.Query(ctx, `
		SELECT `+cohortColumns+` FROM cohorts
		WHERE created_by = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]Cohort, 0, 16)
	for rows.Next() {
		c, err := scanCohort(rows)
		if err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}
