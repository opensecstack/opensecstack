package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/sinauth/internal/user"
	"github.com/spf13/cobra"
)

// newPromoteAdminTestCmd builds a standalone *cobra.Command carrying just
// the --revoke flag runPromoteAdmin reads, independent of the package-level
// promoteAdminCmd (which must not be mutated by tests, since it is the
// actual CLI wiring used by main()).
func newPromoteAdminTestCmd(revoke bool) *cobra.Command {
	cmd := &cobra.Command{Use: "promote-admin"}
	cmd.Flags().Bool("revoke", revoke, "")
	return cmd
}

// setPromoteAdminEnv wires the env vars config.Load() needs so
// runPromoteAdmin (and the other DB-backed cmd/sinauth commands) can build
// a *config.Config pointed at the live test database, using t.Setenv so
// each var is restored automatically at test end.
func setPromoteAdminEnv(t *testing.T, dbURL string) {
	t.Helper()
	t.Setenv("SINAUTH_DB_URL", dbURL)
	t.Setenv("SINAUTH_ISSUER", "https://sinauth.test")
	t.Setenv("SINAUTH_SIGNING_KEY_PATH", filepath.Join(t.TempDir(), "sinauth.pem"))
	t.Setenv("SINAUTH_DEV_MODE", "")
}

func createPromoteAdminTestUser(t *testing.T, username string) *user.User {
	t.Helper()
	ctx := context.Background()
	pool := requireDB(t) // requireDB itself also skips if SINAUTH_TEST_DB_URL unset
	store := user.NewStore(pool)
	u := &user.User{Username: username, Email: username + "@example.com"}
	if err := store.Create(ctx, u); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })
	return u
}

// TestRunPromoteAdmin_GrantsAndRevokes exercises the full runPromoteAdmin
// CLI path (config.Load -> DB connect -> user.Store.SetPlatformAdmin)
// against the real test database: granting platform-admin standing to a
// freshly created user, then revoking it via --revoke, verifying the
// users.is_platform_admin flag both times.
func TestRunPromoteAdmin_GrantsAndRevokes(t *testing.T) {
	dbURL := requireDBURL(t)
	setPromoteAdminEnv(t, dbURL)

	username := fmt.Sprintf("promotetest%d", time.Now().UnixNano())
	u := createPromoteAdminTestUser(t, username)

	if err := runPromoteAdmin(newPromoteAdminTestCmd(false), []string{u.Email}); err != nil {
		t.Fatalf("runPromoteAdmin (grant): %v", err)
	}

	pool := requireDB(t)
	store := user.NewStore(pool)
	isAdmin, err := store.IsPlatformAdmin(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("IsPlatformAdmin: %v", err)
	}
	if !isAdmin {
		t.Fatal("runPromoteAdmin (grant) did not set is_platform_admin=true")
	}

	// Now revoke.
	if err := runPromoteAdmin(newPromoteAdminTestCmd(true), []string{u.Email}); err != nil {
		t.Fatalf("runPromoteAdmin (revoke): %v", err)
	}
	isAdmin, err = store.IsPlatformAdmin(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("IsPlatformAdmin after revoke: %v", err)
	}
	if isAdmin {
		t.Fatal("runPromoteAdmin (--revoke) did not clear is_platform_admin")
	}
}

// TestRunPromoteAdmin_UnknownEmail proves an email with no matching user
// row is reported as an error rather than silently succeeding.
func TestRunPromoteAdmin_UnknownEmail(t *testing.T) {
	dbURL := requireDBURL(t)
	setPromoteAdminEnv(t, dbURL)

	err := runPromoteAdmin(newPromoteAdminTestCmd(false), []string{fmt.Sprintf("nobody-%d@example.com", time.Now().UnixNano())})
	if err == nil {
		t.Fatal("runPromoteAdmin: expected an error for an unknown email, got nil")
	}
	if !strings.Contains(err.Error(), "no user with email") {
		t.Errorf("runPromoteAdmin error = %q, want it to mention 'no user with email'", err.Error())
	}
}

// TestRunPromoteAdmin_ConfigError proves a missing required config value
// (here, SINAUTH_ISSUER, required outside dev mode) surfaces as a wrapped
// "config:" error before any DB connection is attempted.
func TestRunPromoteAdmin_ConfigError(t *testing.T) {
	t.Setenv("SINAUTH_DB_URL", "postgres://ignored/ignored")
	t.Setenv("SINAUTH_ISSUER", "")
	t.Setenv("SINAUTH_SIGNING_KEY_PATH", "")
	t.Setenv("SINAUTH_DEV_MODE", "")

	err := runPromoteAdmin(newPromoteAdminTestCmd(false), []string{"whoever@example.com"})
	if err == nil {
		t.Fatal("runPromoteAdmin: expected a config error, got nil")
	}
	if !strings.Contains(err.Error(), "config:") {
		t.Errorf("runPromoteAdmin error = %q, want it to start with 'config:'", err.Error())
	}
}

// requireDBURL is like requireDB but returns the DSN string itself (for
// tests that need to set SINAUTH_DB_URL) while still skipping consistently
// when SINAUTH_TEST_DB_URL is unset.
func requireDBURL(t *testing.T) string {
	t.Helper()
	requireDB(t) // reuse the same skip + reachability proof
	return os.Getenv("SINAUTH_TEST_DB_URL")
}
