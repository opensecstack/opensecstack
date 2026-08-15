//go:build integration

// Integration tests for UserStore. Requires CYBERPATH_TEST_DB_URL pointing
// at a fully-migrated cyberpath schema; otherwise skipped.
package db

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func userTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
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
	t.Cleanup(pool.Close)
	return pool
}

func seedUserTenant(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
		tenantID, "u-"+tenantID.String()[:8], "user-store-test-tenant"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID)
	})
	return tenantID
}

func TestUserStore_CreateFindByEmailFindByID(t *testing.T) {
	pool := userTestPool(t)
	ctx := context.Background()
	tenantID := seedUserTenant(t, pool)
	store := NewUserStore(pool)

	email := "alice-" + uuid.NewString()[:8] + "@Test.Local" // mixed case, tests LOWER() match
	u := &User{
		TenantID:    tenantID,
		Email:       email,
		DisplayName: "Alice",
	}
	if err := store.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.ID == uuid.Nil {
		t.Fatal("Create: id not populated")
	}
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Fatal("Create: timestamps not populated")
	}
	// Defaults applied when unset.
	if u.Locale != "sq" {
		t.Fatalf("Create: expected default locale 'sq', got %q", u.Locale)
	}
	if u.Role != "learner" {
		t.Fatalf("Create: expected default role 'learner', got %q", u.Role)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, u.ID)
	})

	got2, err := store.FindByEmail(ctx, email)
	if err != nil {
		t.Fatalf("FindByEmail: %v", err)
	}
	if got2.ID != u.ID {
		t.Fatalf("FindByEmail: id mismatch got %s want %s", got2.ID, u.ID)
	}

	byID, err := store.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if byID.Email != email {
		t.Fatalf("FindByID: email mismatch got %q want %q", byID.Email, email)
	}
}

func TestUserStore_FindByEmail_CaseInsensitive(t *testing.T) {
	pool := userTestPool(t)
	ctx := context.Background()
	tenantID := seedUserTenant(t, pool)
	store := NewUserStore(pool)

	local := "bob-" + uuid.NewString()[:8]
	email := local + "@test.local"
	u := &User{TenantID: tenantID, Email: email, DisplayName: "Bob"}
	if err := store.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, u.ID)
	})

	// Reconstruct the email fully upper-cased.
	upper := ""
	for _, r := range email {
		if r >= 'a' && r <= 'z' {
			upper += string(r - 32)
		} else {
			upper += string(r)
		}
	}

	got, err := store.FindByEmail(ctx, upper)
	if err != nil {
		t.Fatalf("FindByEmail (uppercased): %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("FindByEmail (uppercased): id mismatch got %s want %s", got.ID, u.ID)
	}
}

func TestUserStore_FindByEmail_NotFound(t *testing.T) {
	pool := userTestPool(t)
	ctx := context.Background()
	store := NewUserStore(pool)

	_, err := store.FindByEmail(ctx, "nobody-"+uuid.NewString()+"@nowhere.test")
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}

	_, err = store.FindByID(ctx, uuid.New())
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("FindByID expected ErrUserNotFound, got %v", err)
	}
}

func TestUserStore_UpdatePasswordHash(t *testing.T) {
	pool := userTestPool(t)
	ctx := context.Background()
	tenantID := seedUserTenant(t, pool)
	store := NewUserStore(pool)

	u := &User{TenantID: tenantID, Email: "pw-" + uuid.NewString()[:8] + "@test.local"}
	if err := store.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, u.ID)
	})

	if err := store.UpdatePasswordHash(ctx, u.ID, "argon2id$fakehash"); err != nil {
		t.Fatalf("UpdatePasswordHash: %v", err)
	}

	got, err := store.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.PasswordHash != "argon2id$fakehash" {
		t.Fatalf("PasswordHash not persisted: got %q", got.PasswordHash)
	}
	if got.PasswordUpdatedAt == nil {
		t.Fatal("PasswordUpdatedAt not stamped")
	}

	if err := store.UpdatePasswordHash(ctx, uuid.New(), "x"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("UpdatePasswordHash(unknown id) expected ErrUserNotFound, got %v", err)
	}
}

func TestUserStore_SoftDeleteAndRestore(t *testing.T) {
	pool := userTestPool(t)
	ctx := context.Background()
	tenantID := seedUserTenant(t, pool)
	store := NewUserStore(pool)

	email := "del-" + uuid.NewString()[:8] + "@test.local"
	u := &User{TenantID: tenantID, Email: email}
	if err := store.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, u.ID)
	})

	if err := store.SoftDelete(ctx, u.ID); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}

	// Excluded from live lookups after soft delete.
	if _, err := store.FindByID(ctx, u.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("FindByID after delete expected ErrUserNotFound, got %v", err)
	}
	if _, err := store.FindByEmail(ctx, email); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("FindByEmail after delete expected ErrUserNotFound, got %v", err)
	}

	// Idempotent re-delete: no error.
	if err := store.SoftDelete(ctx, u.ID); err != nil {
		t.Fatalf("SoftDelete (repeat) expected nil, got %v", err)
	}

	// Deleting a non-existent id is a real error.
	if err := store.SoftDelete(ctx, uuid.New()); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("SoftDelete(unknown id) expected ErrUserNotFound, got %v", err)
	}

	if err := store.Restore(ctx, u.ID); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, err := store.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindByID after restore: %v", err)
	}
	if got.DeletedAt != nil {
		t.Fatal("Restore did not clear deleted_at")
	}

	if err := store.Restore(ctx, uuid.New()); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("Restore(unknown id) expected ErrUserNotFound, got %v", err)
	}
}
