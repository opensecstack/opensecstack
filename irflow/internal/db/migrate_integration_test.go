//go:build integration

package db

import (
	"context"
	"testing"
)

// TestMigrations_IdempotentWithSchemaMigrationsTable validates the guarantee
// the migrate command relies on: re-running the same .sql files multiple
// times is a no-op once schema_migrations has recorded them.
func TestMigrations_IdempotentWithSchemaMigrationsTable(t *testing.T) {
	pool := setupDB(t) // applies migrations once
	ctx := context.Background()

	var count int
	if err := pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count < 2 {
		t.Fatalf("expected at least 2 migrations recorded, got %d", count)
	}

	// Each domain table should exist after migrations applied.
	for _, table := range []string{
		"incidents", "incident_actions", "ioc_enrichments", "timeline_entries",
		"playbooks", "playbook_executions",
	} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_name = $1
			)`, table).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s should exist after migration", table)
		}
	}
}

func TestMigrations_SchemaMigrationsHasExpectedVersions(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	rows, err := pool.Query(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer rows.Close()

	got := map[string]bool{}
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		got[v] = true
	}
	for _, want := range []string{"001_initial.sql", "002_playbooks.sql"} {
		if !got[want] {
			t.Errorf("schema_migrations missing %s (got %v)", want, got)
		}
	}
}
