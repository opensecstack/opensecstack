//go:build integration

package user

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used in internal/organization/store_test.go.
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("SINAUTH_TEST_DB_URL")
	if dbURL == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping user store integration test")
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestStoreIsPlatformAdmin_DefaultsFalse(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	username := fmt.Sprintf("plainuser%d", time.Now().UnixNano())
	u := &User{Username: username, Email: username + "@example.com"}
	if err := s.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	isAdmin, err := s.IsPlatformAdmin(ctx, u.ID)
	if err != nil {
		t.Fatalf("IsPlatformAdmin: %v", err)
	}
	if isAdmin {
		t.Fatal("newly created user should not be a platform admin by default")
	}
}

func TestStoreSetPlatformAdmin_PromoteAndRevoke(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	username := fmt.Sprintf("futureadmin%d", time.Now().UnixNano())
	email := username + "@example.com"
	u := &User{Username: username, Email: email}
	if err := s.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	// Bootstrap: promote by email (the documented first-admin procedure).
	found, err := s.SetPlatformAdmin(ctx, email, true)
	if err != nil {
		t.Fatalf("SetPlatformAdmin(promote): %v", err)
	}
	if !found {
		t.Fatal("expected SetPlatformAdmin to find the user by email")
	}

	isAdmin, err := s.IsPlatformAdmin(ctx, u.ID)
	if err != nil {
		t.Fatalf("IsPlatformAdmin after promote: %v", err)
	}
	if !isAdmin {
		t.Fatal("expected user to be platform admin after SetPlatformAdmin(true)")
	}

	// Revoke.
	found, err = s.SetPlatformAdmin(ctx, email, false)
	if err != nil {
		t.Fatalf("SetPlatformAdmin(revoke): %v", err)
	}
	if !found {
		t.Fatal("expected SetPlatformAdmin to find the user by email on revoke")
	}

	isAdmin, err = s.IsPlatformAdmin(ctx, u.ID)
	if err != nil {
		t.Fatalf("IsPlatformAdmin after revoke: %v", err)
	}
	if isAdmin {
		t.Fatal("expected user to no longer be platform admin after SetPlatformAdmin(false)")
	}
}

func TestStoreSetPlatformAdmin_UnknownEmail(t *testing.T) {
	pool := requireDB(t)
	s := NewStore(pool)
	ctx := context.Background()

	found, err := s.SetPlatformAdmin(ctx, "does-not-exist-"+fmt.Sprint(time.Now().UnixNano())+"@example.com", true)
	if err != nil {
		t.Fatalf("SetPlatformAdmin: %v", err)
	}
	if found {
		t.Fatal("expected found=false for an email with no matching user")
	}
}
