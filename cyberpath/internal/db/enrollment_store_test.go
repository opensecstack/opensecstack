//go:build integration

// Integration tests for EnrollmentStore against the `cohort_enrollments`
// join table. Requires CYBERPATH_TEST_DB_URL; skipped otherwise.
package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// enrollFixture seeds a tenant, an instructor (creator) and a cohort.
func enrollFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (cohortID, instructorID uuid.UUID) {
	t.Helper()

	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "en-"+tenantID.String()[:8], "enroll-test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	instructorID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, role_id) VALUES ($1, $2, $3, 'instructor')`,
		instructorID, tenantID, instructorID.String()+"@test.local"); err != nil {
		t.Fatalf("seed instructor: %v", err)
	}

	cohortID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cohorts (id, tenant_id, name, created_by) VALUES ($1, $2, $3, $4)`,
		cohortID, tenantID, "Enrollment Test Cohort", instructorID); err != nil {
		t.Fatalf("seed cohort: %v", err)
	}

	return cohortID, instructorID
}

func enrollSeedLearner(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`,
		userID, tenantID, userID.String()+"@test.local"); err != nil {
		t.Fatalf("seed learner: %v", err)
	}
	return userID
}

func TestEnrollmentStore_EnrollUnenrollList(t *testing.T) {
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	cohortID, instructorID := enrollFixture(t, ctx, pool)

	var tenantID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM cohorts WHERE id = $1`, cohortID).Scan(&tenantID); err != nil {
		t.Fatalf("lookup tenant: %v", err)
	}
	learnerID := enrollSeedLearner(t, ctx, pool, tenantID)

	store := NewEnrollmentStore(pool)

	enrollment, err := store.Enroll(ctx, cohortID, learnerID, instructorID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if enrollment.CompletionStatus != "planned" {
		t.Fatalf("Enroll: completion_status = %q, want \"planned\" (default)", enrollment.CompletionStatus)
	}
	if enrollment.UnenrolledAt != nil {
		t.Fatalf("Enroll: UnenrolledAt = %v, want nil", enrollment.UnenrolledAt)
	}

	active, err := store.ListActiveByCohort(ctx, cohortID)
	if err != nil {
		t.Fatalf("ListActiveByCohort: %v", err)
	}
	if len(active) != 1 || active[0].ID != enrollment.ID {
		t.Fatalf("ListActiveByCohort: expected our enrollment, got %d rows", len(active))
	}

	if err := store.UpdateCompletionStatus(ctx, enrollment.ID, "in_progress"); err != nil {
		t.Fatalf("UpdateCompletionStatus: %v", err)
	}

	byUser, err := store.ListByUser(ctx, learnerID)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(byUser) != 1 || byUser[0].CompletionStatus != "in_progress" {
		t.Fatalf("ListByUser: unexpected results %+v", byUser)
	}

	if err := store.Unenroll(ctx, cohortID, learnerID); err != nil {
		t.Fatalf("Unenroll: %v", err)
	}

	activeAfter, err := store.ListActiveByCohort(ctx, cohortID)
	if err != nil {
		t.Fatalf("ListActiveByCohort after unenroll: %v", err)
	}
	if len(activeAfter) != 0 {
		t.Fatalf("ListActiveByCohort after unenroll: got %d, want 0", len(activeAfter))
	}

	// Historical row remains visible via ListByUser with dropped status.
	historyAfter, err := store.ListByUser(ctx, learnerID)
	if err != nil {
		t.Fatalf("ListByUser after unenroll: %v", err)
	}
	if len(historyAfter) != 1 || historyAfter[0].CompletionStatus != "dropped" {
		t.Fatalf("ListByUser after unenroll: unexpected results %+v", historyAfter)
	}
	if historyAfter[0].UnenrolledAt == nil {
		t.Fatal("ListByUser after unenroll: UnenrolledAt not set")
	}
}

func TestEnrollmentStore_Enroll_DuplicateActiveRejected(t *testing.T) {
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	cohortID, instructorID := enrollFixture(t, ctx, pool)
	var tenantID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM cohorts WHERE id = $1`, cohortID).Scan(&tenantID); err != nil {
		t.Fatalf("lookup tenant: %v", err)
	}
	learnerID := enrollSeedLearner(t, ctx, pool, tenantID)

	store := NewEnrollmentStore(pool)

	if _, err := store.Enroll(ctx, cohortID, learnerID, instructorID); err != nil {
		t.Fatalf("Enroll (first): %v", err)
	}

	// Second active enrollment for the same (cohort, user) violates
	// uq_cohort_enrollments_active.
	if _, err := store.Enroll(ctx, cohortID, learnerID, instructorID); err == nil {
		t.Fatal("Enroll (duplicate active): expected unique constraint violation, got nil")
	}

	// After unenrolling, re-enrollment must succeed (partial unique index
	// only covers unenrolled_at IS NULL rows).
	if err := store.Unenroll(ctx, cohortID, learnerID); err != nil {
		t.Fatalf("Unenroll: %v", err)
	}
	if _, err := store.Enroll(ctx, cohortID, learnerID, instructorID); err != nil {
		t.Fatalf("Enroll (re-enroll after unenroll): %v", err)
	}
}

func TestEnrollmentStore_Unenroll_Idempotent(t *testing.T) {
	url := os.Getenv("CYBERPATH_TEST_DB_URL")
	if url == "" {
		t.Skip("CYBERPATH_TEST_DB_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	cohortID, _ := enrollFixture(t, ctx, pool)
	store := NewEnrollmentStore(pool)

	// Unenrolling a (cohort, user) pair with no active row is a no-op,
	// not an error.
	if err := store.Unenroll(ctx, cohortID, uuid.New()); err != nil {
		t.Fatalf("Unenroll (no active row): %v", err)
	}
}
