package cmd

import (
	"os"
	"testing"

	"github.com/spf13/viper"
)

func TestMigrateCmd_RegisteredOnRoot(t *testing.T) {
	found := false
	for _, c := range rootCmd.Commands() {
		if c.Name() == "migrate" {
			found = true
			if c.Short == "" {
				t.Error("expected non-empty Short description")
			}
		}
	}
	if !found {
		t.Fatal("migrate command not registered on rootCmd")
	}
}

func TestMigrateCmd_FlagDefaults(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"rollback", "0"},
		{"target", "-1"},
		{"status", "false"},
		{"force", "-1"},
	}
	for _, tc := range cases {
		f := migrateCmd.Flags().Lookup(tc.name)
		if f == nil {
			t.Fatalf("flag %q not defined", tc.name)
		}
		if f.DefValue != tc.want {
			t.Errorf("flag %q default = %q, want %q", tc.name, f.DefValue, tc.want)
		}
	}
}

// resetMigrateFlags restores the package-level flag vars migrateCmd.RunE
// reads, so tests that invoke RunE directly don't leak state into each
// other or into unrelated tests in this package.
func resetMigrateFlags(t *testing.T) {
	t.Helper()
	origRollback, origTarget, origStatus, origForce := migrateRollback, migrateTarget, migrateStatus, migrateForce
	t.Cleanup(func() {
		migrateRollback, migrateTarget, migrateStatus, migrateForce = origRollback, origTarget, origStatus, origForce
	})
	migrateRollback, migrateTarget, migrateStatus, migrateForce = 0, -1, false, -1
}

func TestMigrateCmd_RunE_NoDatabase_ReturnsError(t *testing.T) {
	resetMigrateFlags(t)
	viper.Set("db.url", "not-a-valid-dsn ::")
	defer viper.Set("db.url", nil)

	if err := migrateCmd.RunE(migrateCmd, nil); err == nil {
		t.Fatal("expected error when the configured DSN is invalid")
	}
}

// TestMigrateCmd_RunE_Status_Integration exercises the full RunE happy path
// against the disposable test database (--status is read-only, so it's safe
// to run alongside internal/db/store's own migration-running integration
// tests without racing their schema state).
func TestMigrateCmd_RunE_Status_Integration(t *testing.T) {
	dsn := os.Getenv("THREATFLOW_TEST_DB_URL")
	if dsn == "" {
		t.Skip("THREATFLOW_TEST_DB_URL not set; skipping migrate cmd integration test")
	}
	resetMigrateFlags(t)
	viper.Set("db.url", dsn)
	defer viper.Set("db.url", nil)

	migrateStatus = true
	if err := migrateCmd.RunE(migrateCmd, nil); err != nil {
		t.Fatalf("RunE (--status): %v", err)
	}
}

// TestMigrateCmd_RunE_Default_Integration exercises the "apply pending
// migrations" default branch. Up() is idempotent, matching the safety
// rationale used by internal/db's own migrate_test.go.
func TestMigrateCmd_RunE_Default_Integration(t *testing.T) {
	dsn := os.Getenv("THREATFLOW_TEST_DB_URL")
	if dsn == "" {
		t.Skip("THREATFLOW_TEST_DB_URL not set; skipping migrate cmd integration test")
	}
	resetMigrateFlags(t)
	viper.Set("db.url", dsn)
	defer viper.Set("db.url", nil)

	if err := migrateCmd.RunE(migrateCmd, nil); err != nil {
		t.Fatalf("RunE (default apply): %v", err)
	}
}
