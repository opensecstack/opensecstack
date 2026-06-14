// Package db — enrollment_store manages the `cohort_enrollments` join table.
// One active row per (cohort, user); historical rows kept with unenrolled_at set.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CohortEnrollment mirrors a row in `cohort_enrollments`.
type CohortEnrollment struct {
	ID               uuid.UUID  `json:"id"`
	CohortID         uuid.UUID  `json:"cohort_id"`
	UserID           uuid.UUID  `json:"user_id"`
	EnrolledAt       time.Time  `json:"enrolled_at"`
	EnrolledBy       uuid.UUID  `json:"enrolled_by"`
	UnenrolledAt     *time.Time `json:"unenrolled_at,omitempty"`
	CompletionStatus string     `json:"completion_status"`
}

// EnrollmentStore wraps a pgx pool for `cohort_enrollments`.
type EnrollmentStore struct {
	Pool *pgxpool.Pool
}

// NewEnrollmentStore wires an EnrollmentStore.
func NewEnrollmentStore(pool *pgxpool.Pool) *EnrollmentStore { return &EnrollmentStore{Pool: pool} }

const enrollmentColumns = `id, cohort_id, user_id, enrolled_at, enrolled_by, unenrolled_at, completion_status`

func scanEnrollment(row interface {
	Scan(dest ...any) error
}) (*CohortEnrollment, error) {
	var e CohortEnrollment
	if err := row.Scan(&e.ID, &e.CohortID, &e.UserID, &e.EnrolledAt, &e.EnrolledBy, &e.UnenrolledAt, &e.CompletionStatus); err != nil {
		return nil, err
	}
	return &e, nil
}

// Enroll inserts an active enrollment. Fails if an active row already exists
// for (cohort, user) due to the partial unique index uq_cohort_enrollments_active.
func (s *EnrollmentStore) Enroll(ctx context.Context, cohortID, userID, byUserID uuid.UUID) (*CohortEnrollment, error) {
	const op = "enrollment.Enroll"
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO cohort_enrollments (id, cohort_id, user_id, enrolled_by)
		VALUES ($1, $2, $3, $4)
		RETURNING `+enrollmentColumns,
		uuid.New(), cohortID, userID, byUserID,
	)
	out, err := scanEnrollment(row)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	return out, nil
}

// Unenroll marks the active enrollment for (cohort, user) as unenrolled. Idempotent.
func (s *EnrollmentStore) Unenroll(ctx context.Context, cohortID, userID uuid.UUID) error {
	const op = "enrollment.Unenroll"
	_, err := s.Pool.Exec(ctx, `
		UPDATE cohort_enrollments
		SET unenrolled_at = now(), completion_status = 'dropped'
		WHERE cohort_id = $1 AND user_id = $2 AND unenrolled_at IS NULL`,
		cohortID, userID)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}

// ListActiveByCohort returns rows that are still active (unenrolled_at IS NULL).
func (s *EnrollmentStore) ListActiveByCohort(ctx context.Context, cohortID uuid.UUID) ([]CohortEnrollment, error) {
	const op = "enrollment.ListActiveByCohort"
	rows, err := s.Pool.Query(ctx, `
		SELECT `+enrollmentColumns+` FROM cohort_enrollments
		WHERE cohort_id = $1 AND unenrolled_at IS NULL
		ORDER BY enrolled_at`, cohortID)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]CohortEnrollment, 0, 32)
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}

// ListByUser returns every enrollment row for a user — active and historical.
func (s *EnrollmentStore) ListByUser(ctx context.Context, userID uuid.UUID) ([]CohortEnrollment, error) {
	const op = "enrollment.ListByUser"
	rows, err := s.Pool.Query(ctx, `
		SELECT `+enrollmentColumns+` FROM cohort_enrollments
		WHERE user_id = $1
		ORDER BY enrolled_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store/%s: %w", op, err)
	}
	defer rows.Close()

	out := make([]CohortEnrollment, 0, 8)
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, fmt.Errorf("store/%s: scan: %w", op, err)
		}
		out = append(out, *e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store/%s: rows: %w", op, err)
	}
	return out, nil
}

// UpdateCompletionStatus sets completion_status. Caller validates the value
// (planned|in_progress|completed|dropped) — DB CHECK enforces the same set.
func (s *EnrollmentStore) UpdateCompletionStatus(ctx context.Context, id uuid.UUID, status string) error {
	const op = "enrollment.UpdateCompletionStatus"
	_, err := s.Pool.Exec(ctx, `
		UPDATE cohort_enrollments SET completion_status = $2 WHERE id = $1`,
		id, status)
	if err != nil {
		return fmt.Errorf("store/%s: %w", op, err)
	}
	return nil
}
