//go:build integration

// Integration tests for RoleStore against the `roles` RBAC catalogue
// seeded by migration 0002. Read-only store: no seeding/cleanup needed,
// just assert against the known catalogue. Requires CYBERPATH_TEST_DB_URL;
// skipped otherwise.
package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRoleStore_Get(t *testing.T) {
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

	store := NewRoleStore(pool)

	got, err := store.Get(ctx, "learner")
	if err != nil {
		t.Fatalf("Get(learner): %v", err)
	}
	if got.ID != "learner" {
		t.Fatalf("Get(learner): id = %q, want \"learner\"", got.ID)
	}
	if len(got.Permissions) == 0 {
		t.Fatal("Get(learner): expected non-empty permissions JSON")
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("Get(learner): CreatedAt not populated")
	}
}

func TestRoleStore_Get_NotFound(t *testing.T) {
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

	store := NewRoleStore(pool)

	if _, err := store.Get(ctx, "does-not-exist-role"); err == nil {
		t.Fatal("Get: expected error for unknown role id, got nil")
	}
}

func TestRoleStore_List(t *testing.T) {
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

	store := NewRoleStore(pool)

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	want := map[string]bool{"admin": true, "instructor": true, "learner": true, "auditor": true}
	seen := map[string]bool{}
	for _, r := range list {
		seen[r.ID] = true
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("List: expected seeded role %q in results", id)
		}
	}

	// Ordered by id (stable for UI listing).
	for i := 1; i < len(list); i++ {
		if list[i-1].ID > list[i].ID {
			t.Fatalf("List: results not ordered by id: %q before %q", list[i-1].ID, list[i].ID)
		}
	}
}
