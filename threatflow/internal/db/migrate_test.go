package db

import "testing"

func TestNewMigrator_InvalidDSN_ReturnsError(t *testing.T) {
	_, err := NewMigrator("not-a-valid-dsn ::")
	if err == nil {
		t.Fatal("expected error for invalid DSN, got nil")
	}
}

// TestMigrator_UpAndStatus exercises the happy path against the shared
// disposable test database. It intentionally never calls Down/Target/Force
// against this DSN: internal/db/store's own integration tests run
// migrations against the same "threatflow_test" schema concurrently (as
// separate `go test` package binaries), so tearing down or rewinding the
// schema version here would race with — and could break — those tests.
// Up() is idempotent and safe to run concurrently (golang-migrate takes a
// database-level advisory lock), which is why it's the only mutating
// operation exercised here.
func TestMigrator_UpAndStatus(t *testing.T) {
	dsn := testDSN(t)

	mg, err := NewMigrator(dsn)
	if err != nil {
		t.Fatalf("NewMigrator: %v", err)
	}
	defer mg.Close()

	if err := mg.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	version, dirty, err := mg.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if dirty {
		t.Error("expected schema not to be dirty after Up")
	}
	if version == 0 {
		t.Error("expected non-zero version after applying migrations")
	}

	// Calling Up again is a no-op and must not surface ErrNoChange as an error.
	if err := mg.Up(); err != nil {
		t.Fatalf("second Up: %v", err)
	}
}

func TestMigrator_Close_IsSafeAfterUse(t *testing.T) {
	dsn := testDSN(t)

	mg, err := NewMigrator(dsn)
	if err != nil {
		t.Fatalf("NewMigrator: %v", err)
	}
	if err := mg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
