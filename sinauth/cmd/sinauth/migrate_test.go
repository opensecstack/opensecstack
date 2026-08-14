package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used across the repo (e.g.
// internal/organization/store_test.go, internal/api/server_admin_test.go).
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("SINAUTH_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping cmd/sinauth DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// fakeDirEntry is a minimal os.DirEntry fake so sqlFileNames can be tested
// against a synthetic directory listing without touching the filesystem.
type fakeDirEntry struct {
	name  string
	isDir bool
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return f.isDir }
func (f fakeDirEntry) Type() fs.FileMode          { return 0 }
func (f fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestSQLFileNames_FiltersAndSorts(t *testing.T) {
	entries := []os.DirEntry{
		fakeDirEntry{name: "003_third.sql"},
		fakeDirEntry{name: "001_first.sql"},
		fakeDirEntry{name: "readme.md"},
		fakeDirEntry{name: "subdir", isDir: true},
		fakeDirEntry{name: "002_second.sql"},
		fakeDirEntry{name: "not_sql.SQL"}, // wrong case, must be excluded — suffix match is case-sensitive
	}

	got := sqlFileNames(entries)
	want := []string{"001_first.sql", "002_second.sql", "003_third.sql"}

	if len(got) != len(want) {
		t.Fatalf("sqlFileNames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sqlFileNames = %v, want %v", got, want)
		}
	}
}

func TestSQLFileNames_EmptyDir(t *testing.T) {
	got := sqlFileNames(nil)
	if len(got) != 0 {
		t.Errorf("sqlFileNames(nil) = %v, want empty", got)
	}
}

func TestPendingFiles_ExcludesApplied(t *testing.T) {
	files := []string{"001_a.sql", "002_b.sql", "003_c.sql"}
	applied := map[string]bool{"001_a.sql": true, "003_c.sql": true}

	got := pendingFiles(files, applied)
	want := []string{"002_b.sql"}

	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("pendingFiles = %v, want %v", got, want)
	}
}

func TestPendingFiles_NoneApplied(t *testing.T) {
	files := []string{"001_a.sql", "002_b.sql"}
	got := pendingFiles(files, map[string]bool{})
	if len(got) != 2 {
		t.Errorf("pendingFiles = %v, want both files pending", got)
	}
}

func TestPendingFiles_AllApplied(t *testing.T) {
	files := []string{"001_a.sql", "002_b.sql"}
	applied := map[string]bool{"001_a.sql": true, "002_b.sql": true}
	got := pendingFiles(files, applied)
	if len(got) != 0 {
		t.Errorf("pendingFiles = %v, want none pending", got)
	}
}

// TestApplyMigration_AppliesAndRecords proves applyMigration runs the given
// SQL and records it in schema_migrations within a single transaction,
// against a real database. Uses a uniquely-named scratch table and a
// uniquely-named migration filename so this cannot collide with rows any
// other parallel test suite writes to the shared schema_migrations table,
// and cleans up both after itself.
func TestApplyMigration_AppliesAndRecords(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()

	// Ensure the tracking table this function depends on exists — runMigrate
	// normally creates it, but this test calls applyMigration directly.
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		t.Fatalf("ensure schema_migrations: %v", err)
	}

	suffix := time.Now().UnixNano()
	tableName := fmt.Sprintf("cmd_sinauth_migrate_probe_%d", suffix)
	migrationName := fmt.Sprintf("999999_cmd_sinauth_test_%d.sql", suffix)
	sql := fmt.Sprintf(`CREATE TABLE %s (id INT PRIMARY KEY)`, tableName)

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, tableName))
		_, _ = pool.Exec(ctx, `DELETE FROM schema_migrations WHERE filename=$1`, migrationName)
	})

	if err := applyMigration(ctx, pool, migrationName, sql); err != nil {
		t.Fatalf("applyMigration: %v", err)
	}

	var exists bool
	err = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`, tableName).Scan(&exists)
	if err != nil {
		t.Fatalf("check table exists: %v", err)
	}
	if !exists {
		t.Error("applyMigration did not create the target table")
	}

	var recorded bool
	err = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE filename=$1)`, migrationName).Scan(&recorded)
	if err != nil {
		t.Fatalf("check schema_migrations row: %v", err)
	}
	if !recorded {
		t.Error("applyMigration did not record the migration filename in schema_migrations")
	}
}

// TestApplyMigration_RollsBackOnFailure proves the transactional guarantee:
// if the migration SQL fails, neither the (partial) DDL nor the
// schema_migrations row are committed.
func TestApplyMigration_RollsBackOnFailure(t *testing.T) {
	pool := requireDB(t)
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		t.Fatalf("ensure schema_migrations: %v", err)
	}

	migrationName := fmt.Sprintf("999999_cmd_sinauth_fail_%d.sql", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM schema_migrations WHERE filename=$1`, migrationName)
	})

	err = applyMigration(ctx, pool, migrationName, `THIS IS NOT VALID SQL;`)
	if err == nil {
		t.Fatal("applyMigration: expected an error for invalid SQL, got nil")
	}

	var recorded bool
	qerr := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE filename=$1)`, migrationName).Scan(&recorded)
	if qerr != nil {
		t.Fatalf("check schema_migrations row: %v", qerr)
	}
	if recorded {
		t.Error("applyMigration recorded the migration filename despite the SQL failing — transaction did not roll back")
	}
}

// newMigrateTestCmd builds a standalone *cobra.Command carrying just the
// --dir flag runMigrate reads, independent of the package-level
// migrateCmd (which must not be mutated by tests, since it is the actual
// CLI wiring used by main()).
func newMigrateTestCmd(dir string) *cobra.Command {
	cmd := &cobra.Command{Use: "migrate"}
	cmd.Flags().String("dir", dir, "")
	return cmd
}

// TestRunMigrate_AppliesAndIsIdempotent exercises the full runMigrate CLI
// path (config.Load -> DB connect -> ensure schema_migrations -> read
// applied -> scan dir -> apply pending) against the real database. It does
// not start any listener (unlike runServe), so it is safe to run
// end-to-end here per the same reasoning applyMigration's tests use: a
// uniquely-named scratch table and migration filename mean this cannot
// collide with concurrent parallel test suites sharing the database, and
// everything is cleaned up afterward. Running it twice in a row also
// proves the "no pending migrations" idempotent-rerun path.
func TestRunMigrate_AppliesAndIsIdempotent(t *testing.T) {
	dbURL := requireDBURL(t)
	t.Setenv("SINAUTH_DB_URL", dbURL)
	t.Setenv("SINAUTH_ISSUER", "https://sinauth.test")
	t.Setenv("SINAUTH_SIGNING_KEY_PATH", filepath.Join(t.TempDir(), "sinauth.pem"))
	t.Setenv("SINAUTH_DEV_MODE", "")

	suffix := time.Now().UnixNano()
	tableName := fmt.Sprintf("cmd_sinauth_runmigrate_probe_%d", suffix)
	migrationFile := fmt.Sprintf("999998_cmd_sinauth_runmigrate_%d.sql", suffix)

	dir := t.TempDir()
	sql := fmt.Sprintf("CREATE TABLE %s (id INT PRIMARY KEY);\n", tableName)
	if err := os.WriteFile(filepath.Join(dir, migrationFile), []byte(sql), 0o644); err != nil {
		t.Fatalf("write migration file: %v", err)
	}
	// A non-.sql file in the same directory must be ignored by sqlFileNames.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not sql"), 0o644); err != nil {
		t.Fatalf("write readme: %v", err)
	}

	pool := requireDB(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, tableName))
		_, _ = pool.Exec(ctx, `DELETE FROM schema_migrations WHERE filename=$1`, migrationFile)
	})

	// First run: applies the one pending migration.
	if err := runMigrate(newMigrateTestCmd(dir), nil); err != nil {
		t.Fatalf("runMigrate (first run): %v", err)
	}

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`, tableName).Scan(&exists); err != nil {
		t.Fatalf("check table exists: %v", err)
	}
	if !exists {
		t.Fatal("runMigrate did not create the target table")
	}

	// Second run: the migration is already recorded, so this exercises the
	// "no pending migrations" branch and must not error or re-apply.
	if err := runMigrate(newMigrateTestCmd(dir), nil); err != nil {
		t.Fatalf("runMigrate (second, idempotent run): %v", err)
	}
}

// TestRunMigrate_MissingDirErrors proves a nonexistent --dir surfaces as a
// wrapped error rather than a panic.
func TestRunMigrate_MissingDirErrors(t *testing.T) {
	dbURL := requireDBURL(t)
	t.Setenv("SINAUTH_DB_URL", dbURL)
	t.Setenv("SINAUTH_ISSUER", "https://sinauth.test")
	t.Setenv("SINAUTH_SIGNING_KEY_PATH", filepath.Join(t.TempDir(), "sinauth.pem"))
	t.Setenv("SINAUTH_DEV_MODE", "")

	missingDir := filepath.Join(t.TempDir(), "does-not-exist")
	err := runMigrate(newMigrateTestCmd(missingDir), nil)
	if err == nil {
		t.Fatal("runMigrate: expected an error for a nonexistent migrations dir, got nil")
	}
	if !strings.Contains(err.Error(), "read migrations dir") {
		t.Errorf("runMigrate error = %q, want it to mention 'read migrations dir'", err.Error())
	}
}

// TestRunMigrate_ConfigError proves a missing required config value aborts
// before any DB or filesystem interaction.
func TestRunMigrate_ConfigError(t *testing.T) {
	t.Setenv("SINAUTH_DB_URL", "postgres://ignored/ignored")
	t.Setenv("SINAUTH_ISSUER", "")
	t.Setenv("SINAUTH_SIGNING_KEY_PATH", "")
	t.Setenv("SINAUTH_DEV_MODE", "")

	err := runMigrate(newMigrateTestCmd("migrations"), nil)
	if err == nil {
		t.Fatal("runMigrate: expected a config error, got nil")
	}
	if !strings.Contains(err.Error(), "config:") {
		t.Errorf("runMigrate error = %q, want it to start with 'config:'", err.Error())
	}
}
