//go:build integration

// Integration tests for CohortStore. Requires CYBERPATH_TEST_DB_URL pointing
// at a fully-migrated cyberpath schema; otherwise the test is skipped.
package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cohortTestPool opens a pool for the cohort store tests, skipping when no
// test DB is configured.
func cohortTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
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
	t.Cleanup(pool.Close)
	return pool
}

// seedCohortTenantUser seeds a tenant + instructor user, registering cleanup.
func seedCohortTenantUser(t *testing.T, pool *pgxpool.Pool) (tenantID, userID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tenantID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "ch-"+tenantID.String()[:8], "cohort-store-test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	userID = uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, role_id) VALUES ($1, $2, $3, 'instructor')`,
		userID, tenantID, userID.String()+"@test.local"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return tenantID, userID
}

func TestCohortStore_CRUD(t *testing.T) {
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

	// Seed a tenant and an instructor user inline so the test is hermetic
	// against whatever rows already exist in the target DB.
	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "t-"+tenantID.String()[:8], "test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	userID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, role_id) VALUES ($1, $2, $3, 'instructor')`,
		userID, tenantID, userID.String()+"@test.local"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	store := NewCohortStore(pool)

	created, err := store.Create(ctx, &Cohort{
		TenantID:    tenantID,
		Name:        "Smoke Cohort",
		Description: "integration test",
		CreatedBy:   userID,
		Status:      "planned",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("create: id not populated")
	}

	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "Smoke Cohort" {
		t.Fatalf("name mismatch: got %q", got.Name)
	}

	list, err := store.ListByTenant(ctx, tenantID, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("list: expected our cohort, got %d rows", len(list))
	}

	if err := store.SoftDelete(ctx, created.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	list2, err := store.ListByTenant(ctx, tenantID, "")
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(list2) != 0 {
		t.Fatalf("soft-deleted cohort still listed: %d rows", len(list2))
	}
}

func TestCohortStore_Update(t *testing.T) {
	pool := cohortTestPool(t)
	ctx := context.Background()
	tenantID, userID := seedCohortTenantUser(t, pool)
	store := NewCohortStore(pool)

	created, err := store.Create(ctx, &Cohort{
		TenantID:    tenantID,
		Name:        "Original",
		Description: "before",
		CreatedBy:   userID,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM cohorts WHERE id = $1`, created.ID) })

	created.Name = "Updated"
	created.Description = "after"
	created.Status = "active"
	updated, err := store.Update(ctx, created)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Updated" || updated.Description != "after" || updated.Status != "active" {
		t.Fatalf("update: fields not persisted: %+v", updated)
	}
	if !updated.UpdatedAt.After(created.CreatedAt.Add(-time.Second)) {
		t.Fatalf("update: updated_at not bumped: %+v", updated)
	}

	// Updating a soft-deleted cohort affects no row -> RETURNING yields
	// pgx.ErrNoRows, surfaced wrapped by the store.
	if err := store.SoftDelete(ctx, created.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := store.Update(ctx, created); err == nil {
		t.Fatal("update on soft-deleted cohort: expected error, got nil")
	}

	// Updating a cohort id that never existed.
	ghost := &Cohort{ID: uuid.New(), Name: "ghost", Status: "planned"}
	if _, err := store.Update(ctx, ghost); err == nil {
		t.Fatal("update on unknown cohort: expected error, got nil")
	}
}

func TestCohortStore_Get_NotFound(t *testing.T) {
	pool := cohortTestPool(t)
	ctx := context.Background()
	store := NewCohortStore(pool)

	if _, err := store.Get(ctx, uuid.New()); err == nil {
		t.Fatal("Get(unknown id): expected error, got nil")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("Get(unknown id): expected wrapped pgx.ErrNoRows, got %v", err)
	}
}

func TestCohortStore_Create_InvalidStatus(t *testing.T) {
	pool := cohortTestPool(t)
	ctx := context.Background()
	tenantID, userID := seedCohortTenantUser(t, pool)
	store := NewCohortStore(pool)

	_, err := store.Create(ctx, &Cohort{
		TenantID:  tenantID,
		Name:      "Bad Status",
		CreatedBy: userID,
		Status:    "not-a-real-status",
	})
	if err == nil {
		t.Fatal("Create with invalid status: expected CHECK constraint violation, got nil")
	}
}

func TestCohortStore_LinkTracks(t *testing.T) {
	pool := cohortTestPool(t)
	ctx := context.Background()
	tenantID, userID := seedCohortTenantUser(t, pool)
	store := NewCohortStore(pool)

	created, err := store.Create(ctx, &Cohort{
		TenantID:  tenantID,
		Name:      "Multi Track",
		CreatedBy: userID,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM cohorts WHERE id = $1`, created.ID) })

	trackID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tracks (id, slug, title) VALUES ($1, $2, $3)`,
		trackID, "lt-"+trackID.String()[:8], "Linked Track"); err != nil {
		t.Fatalf("seed track: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM tracks WHERE id = $1`, trackID) })

	// No-op call: both empty.
	if err := store.LinkTracks(ctx, created.ID, nil, nil); err != nil {
		t.Fatalf("LinkTracks no-op: %v", err)
	}

	if err := store.LinkTracks(ctx, created.ID, []uuid.UUID{trackID}, []string{"unresolved-slug", ""}); err != nil {
		t.Fatalf("LinkTracks: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cohort_tracks WHERE cohort_id = $1`, created.ID).Scan(&count); err != nil {
		t.Fatalf("count links: %v", err)
	}
	// One uuid link + one slug link; the empty-string slug is skipped.
	if count != 2 {
		t.Fatalf("expected 2 cohort_tracks rows, got %d", count)
	}

	// Replaying the exact same links is a no-op thanks to ON CONFLICT DO NOTHING.
	if err := store.LinkTracks(ctx, created.ID, []uuid.UUID{trackID}, []string{"unresolved-slug"}); err != nil {
		t.Fatalf("LinkTracks replay: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cohort_tracks WHERE cohort_id = $1`, created.ID).Scan(&count); err != nil {
		t.Fatalf("count links after replay: %v", err)
	}
	if count != 2 {
		t.Fatalf("replay duplicated rows: expected 2, got %d", count)
	}
}

func TestCohortStore_ListByInstructor(t *testing.T) {
	pool := cohortTestPool(t)
	ctx := context.Background()
	tenantID, userID := seedCohortTenantUser(t, pool)
	_, otherUserID := seedCohortTenantUser(t, pool)
	store := NewCohortStore(pool)

	mine, err := store.Create(ctx, &Cohort{TenantID: tenantID, Name: "Mine", CreatedBy: userID})
	if err != nil {
		t.Fatalf("create mine: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM cohorts WHERE id = $1`, mine.ID) })

	theirs, err := store.Create(ctx, &Cohort{TenantID: tenantID, Name: "Theirs", CreatedBy: otherUserID})
	if err != nil {
		t.Fatalf("create theirs: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM cohorts WHERE id = $1`, theirs.ID) })

	list, err := store.ListByInstructor(ctx, userID)
	if err != nil {
		t.Fatalf("ListByInstructor: %v", err)
	}
	if len(list) != 1 || list[0].ID != mine.ID {
		t.Fatalf("ListByInstructor: expected only 'mine', got %+v", list)
	}
}
