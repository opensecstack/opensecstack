package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// chdirToModuleRoot changes into the apiguard module root for the duration
// of the test, since migrationsDir is a relative path ("migrations") that
// production code only ever resolves correctly when run from there (e.g.
// `go run ./cmd/migrate` invoked from apiguard/) — `go test`'s working
// directory is the package directory (cmd/migrate) instead.
func chdirToModuleRoot(t *testing.T) {
	t.Helper()
	t.Chdir("../..")
	if _, err := os.Stat(migrationsDir); err != nil {
		t.Fatalf("expected %s/ to exist after chdir to module root: %v", migrationsDir, err)
	}
}

func TestMigrationVersion(t *testing.T) {
	cases := map[string]string{
		"001_create_scans.up.sql":   "001_create_scans",
		"014_add_findings.down.sql": "014_add_findings",
		"plain.sql":                 "plain",
	}
	for in, want := range cases {
		if got := migrationVersion(in); got != want {
			t.Errorf("migrationVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListMigrationFiles(t *testing.T) {
	chdirToModuleRoot(t)
	up, err := listMigrationFiles("up")
	if err != nil {
		t.Fatalf("listMigrationFiles(up): %v", err)
	}
	if len(up) == 0 {
		t.Fatal("expected at least one .up.sql migration file in migrations/")
	}
	for i := 1; i < len(up); i++ {
		if up[i-1] > up[i] {
			t.Fatalf("expected sorted migration files, got %v before %v", up[i-1], up[i])
		}
	}

	down, err := listMigrationFiles("down")
	if err != nil {
		t.Fatalf("listMigrationFiles(down): %v", err)
	}
	if len(down) != len(up) {
		t.Errorf("expected matching up/down migration counts, got %d up, %d down", len(up), len(down))
	}
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("MIGRATE_TEST_DB_URL")
	if dsn == "" {
		t.Skip("MIGRATE_TEST_DB_URL not set — skipping live-DB migrate tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestEnsureMigrationsTable_Idempotent(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	if err := ensureMigrationsTable(ctx, pool); err != nil {
		t.Fatalf("first ensureMigrationsTable: %v", err)
	}
	// Calling it again must be a no-op, not an error (CREATE TABLE IF NOT EXISTS).
	if err := ensureMigrationsTable(ctx, pool); err != nil {
		t.Fatalf("second ensureMigrationsTable: %v", err)
	}
}

func TestAppliedVersions_EmptyThenPopulated(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS schema_migrations`); err != nil {
		t.Fatalf("drop schema_migrations: %v", err)
	}
	if err := ensureMigrationsTable(ctx, pool); err != nil {
		t.Fatalf("ensureMigrationsTable: %v", err)
	}

	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		t.Fatalf("appliedVersions: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("expected empty applied set, got %v", applied)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ('001_test'), ('002_test')`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	applied, err = appliedVersions(ctx, pool)
	if err != nil {
		t.Fatalf("appliedVersions after insert: %v", err)
	}
	if !applied["001_test"] || !applied["002_test"] {
		t.Fatalf("expected both versions applied, got %v", applied)
	}

	sorted, err := appliedVersionsSorted(ctx, pool)
	if err != nil {
		t.Fatalf("appliedVersionsSorted: %v", err)
	}
	if len(sorted) != 2 || sorted[0] != "001_test" || sorted[1] != "002_test" {
		t.Fatalf("expected [001_test 002_test] in applied order, got %v", sorted)
	}
}

func TestMigrateUpAndDown_RealMigrations(t *testing.T) {
	chdirToModuleRoot(t)
	pool := testPool(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset schema_migrations: %v", err)
	}
	if err := ensureMigrationsTable(ctx, pool); err != nil {
		t.Fatalf("ensureMigrationsTable: %v", err)
	}

	if err := migrateUp(ctx, pool); err != nil {
		t.Fatalf("migrateUp: %v", err)
	}

	up, err := listMigrationFiles("up")
	if err != nil {
		t.Fatalf("listMigrationFiles: %v", err)
	}
	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		t.Fatalf("appliedVersions: %v", err)
	}
	for _, f := range up {
		ver := migrationVersion(f)
		if !applied[ver] {
			t.Errorf("expected %s to be applied after migrateUp, applied set: %v", ver, applied)
		}
	}

	// Running migrateUp again must be a no-op (all already applied).
	if err := migrateUp(ctx, pool); err != nil {
		t.Fatalf("second migrateUp: %v", err)
	}

	if err := migrateDown(ctx, pool); err != nil {
		t.Fatalf("migrateDown: %v", err)
	}
	appliedAfterDown, err := appliedVersions(ctx, pool)
	if err != nil {
		t.Fatalf("appliedVersions after down: %v", err)
	}
	if len(appliedAfterDown) != len(applied)-1 {
		t.Errorf("expected exactly one migration rolled back, before=%d after=%d", len(applied), len(appliedAfterDown))
	}
}

func TestMigrateDown_NoMigrationsToRollBack(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS schema_migrations CASCADE`); err != nil {
		t.Fatalf("reset schema_migrations: %v", err)
	}
	if err := ensureMigrationsTable(ctx, pool); err != nil {
		t.Fatalf("ensureMigrationsTable: %v", err)
	}

	if err := migrateDown(ctx, pool); err != nil {
		t.Fatalf("migrateDown on empty schema_migrations should be a no-op, got: %v", err)
	}
}
