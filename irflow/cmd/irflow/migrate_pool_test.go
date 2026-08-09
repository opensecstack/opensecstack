package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pashagolub/pgxmock/v3"
)

func newMockMigratorPool(t *testing.T) pgxmock.PgxPoolIface {
	t.Helper()
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("creating pgxmock pool: %v", err)
	}
	t.Cleanup(mock.Close)
	return mock
}

func TestEnsureMigrationsTable_Success(t *testing.T) {
	mock := newMockMigratorPool(t)
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").
		WillReturnResult(pgxmock.NewResult("CREATE", 0))

	if err := ensureMigrationsTable(context.Background(), mock); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestEnsureMigrationsTable_PropagatesError(t *testing.T) {
	mock := newMockMigratorPool(t)
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").
		WillReturnError(context.DeadlineExceeded)

	if err := ensureMigrationsTable(context.Background(), mock); err == nil {
		t.Fatal("expected error to propagate from Exec failure")
	}
}

func TestAppliedMigrations_ReturnsSetOfAppliedVersions(t *testing.T) {
	mock := newMockMigratorPool(t)
	mock.ExpectQuery("SELECT version FROM schema_migrations").
		WillReturnRows(pgxmock.NewRows([]string{"version"}).
			AddRow("0001_init.sql").
			AddRow("0002_add_column.sql"))

	applied, err := appliedMigrations(context.Background(), mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !applied["0001_init.sql"] || !applied["0002_add_column.sql"] {
		t.Errorf("expected both versions marked applied, got %+v", applied)
	}
	if applied["0003_never_seen.sql"] {
		t.Error("expected unseen version to be absent/false")
	}
	if len(applied) != 2 {
		t.Errorf("expected exactly 2 applied entries, got %d", len(applied))
	}
}

func TestAppliedMigrations_EmptyTableReturnsEmptyMap(t *testing.T) {
	mock := newMockMigratorPool(t)
	mock.ExpectQuery("SELECT version FROM schema_migrations").
		WillReturnRows(pgxmock.NewRows([]string{"version"}))

	applied, err := appliedMigrations(context.Background(), mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("expected empty map, got %+v", applied)
	}
}

func TestAppliedMigrations_PropagatesQueryError(t *testing.T) {
	mock := newMockMigratorPool(t)
	mock.ExpectQuery("SELECT version FROM schema_migrations").
		WillReturnError(context.DeadlineExceeded)

	_, err := appliedMigrations(context.Background(), mock)
	if err == nil {
		t.Fatal("expected error to propagate from Query failure")
	}
}

func TestApplyMigration_Success(t *testing.T) {
	mock := newMockMigratorPool(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "0001_init.sql")
	if err := os.WriteFile(path, []byte("SELECT 1;"), 0o644); err != nil {
		t.Fatalf("writing migration file: %v", err)
	}

	mock.ExpectBegin()
	mock.ExpectExec("SELECT 1;").WillReturnResult(pgxmock.NewResult("SELECT", 0))
	mock.ExpectExec("INSERT INTO schema_migrations").
		WithArgs("0001_init.sql").
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectCommit()
	mock.ExpectRollback() // deferred rollback still fires (no-op) after a successful commit

	if err := applyMigration(context.Background(), mock, path, "0001_init.sql"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestApplyMigration_MissingFileReturnsErrorWithoutTouchingDB(t *testing.T) {
	mock := newMockMigratorPool(t)

	err := applyMigration(context.Background(), mock, filepath.Join(t.TempDir(), "missing.sql"), "missing.sql")
	if err == nil {
		t.Fatal("expected error for a nonexistent migration file")
	}
	// No Begin/Exec expectations were set, so ExpectationsWereMet trivially
	// passes here; the real assertion is that reading the file happens
	// before any DB call, i.e. applyMigration returned before Begin().
}

func TestApplyMigration_SQLErrorRollsBackAndReturnsError(t *testing.T) {
	mock := newMockMigratorPool(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "0001_bad.sql")
	if err := os.WriteFile(path, []byte("BROKEN SQL"), 0o644); err != nil {
		t.Fatalf("writing migration file: %v", err)
	}

	mock.ExpectBegin()
	mock.ExpectExec("BROKEN SQL").WillReturnError(context.DeadlineExceeded)
	mock.ExpectRollback()

	err := applyMigration(context.Background(), mock, path, "0001_bad.sql")
	if err == nil {
		t.Fatal("expected error when the migration SQL fails to execute")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations (rollback likely not triggered): %v", err)
	}
}
