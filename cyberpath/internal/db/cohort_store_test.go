//go:build integration

// Smoke test for CohortStore. Requires CYBERPATH_TEST_DB_URL pointing at a
// fully-migrated cyberpath schema; otherwise the test is skipped.
package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

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
