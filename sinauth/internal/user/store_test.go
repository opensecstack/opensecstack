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

// testPool mirrors requireDB in store_admin_test.go — kept as a separate
// small helper here so this file can be read/maintained independently.
func testPool(t *testing.T) *pgxpool.Pool {
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

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano())
}

func mkUser(t *testing.T, s *Store, prefix string) *User {
	t.Helper()
	ctx := context.Background()
	name := uniqueName(prefix)
	u := &User{Username: name, Email: name + "@example.com", PasswordHash: "irrelevant-hash", DisplayName: "Display " + name}
	if err := s.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = s.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })
	return u
}

func TestStore_CreateAndGetters(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	u := mkUser(t, s, "getteruser")

	byUsername, err := s.GetByUsername(ctx, u.Username)
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if byUsername.ID != u.ID || byUsername.Email != u.Email {
		t.Errorf("GetByUsername returned %+v, want id/email matching %+v", byUsername, u)
	}
	if byUsername.PasswordHash != u.PasswordHash {
		t.Errorf("GetByUsername did not round-trip password_hash: got %q want %q", byUsername.PasswordHash, u.PasswordHash)
	}

	byID, err := s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if byID.Username != u.Username {
		t.Errorf("GetByID returned %+v, want username %q", byID, u.Username)
	}

	byEmail, err := s.GetByEmail(ctx, u.Email)
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if byEmail.ID != u.ID {
		t.Errorf("GetByEmail returned %+v, want id %q", byEmail, u.ID)
	}

	if byID.EmailVerified {
		t.Error("newly created user should not be email-verified by default")
	}
	if byID.DeactivatedAt != nil {
		t.Error("newly created user should not be deactivated")
	}
}

func TestStore_GetByUsername_NotFound(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	if _, err := s.GetByUsername(context.Background(), "no-such-user-"+uniqueName("")); err != ErrNotFound {
		t.Fatalf("GetByUsername = %v, want ErrNotFound", err)
	}
}

func TestStore_GetByID_NotFound(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	// A syntactically invalid UUID also exercises the Scan-error branch,
	// which store.go maps to ErrNotFound rather than leaking the raw driver
	// error (avoids distinguishing "malformed id" from "no such id" to a
	// caller, which is the correct choice for an auth-adjacent lookup).
	if _, err := s.GetByID(context.Background(), "00000000-0000-0000-0000-000000000000"); err != ErrNotFound {
		t.Fatalf("GetByID(random uuid) = %v, want ErrNotFound", err)
	}
	if _, err := s.GetByID(context.Background(), "not-a-uuid"); err != ErrNotFound {
		t.Fatalf("GetByID(malformed) = %v, want ErrNotFound", err)
	}
}

func TestStore_GetByEmail_NotFound(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	if _, err := s.GetByEmail(context.Background(), "nobody-"+uniqueName("")+"@example.com"); err != ErrNotFound {
		t.Fatalf("GetByEmail = %v, want ErrNotFound", err)
	}
}

func TestStore_Create_DuplicateUsername(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	u1 := mkUser(t, s, "dupuser")

	u2 := &User{Username: u1.Username, Email: uniqueName("otheremail") + "@example.com"}
	err := s.Create(ctx, u2)
	if err != ErrDuplicate {
		t.Fatalf("Create with duplicate username = %v, want ErrDuplicate", err)
	}
}

func TestStore_Create_DuplicateEmail(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	u1 := mkUser(t, s, "dupemail")

	u2 := &User{Username: uniqueName("otheruser"), Email: u1.Email}
	err := s.Create(ctx, u2)
	if err != ErrDuplicate {
		t.Fatalf("Create with duplicate email = %v, want ErrDuplicate", err)
	}
}

func TestStore_List(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	u := mkUser(t, s, "listuser")

	users, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, got := range users {
		if got.ID == u.ID {
			found = true
			if got.Username != u.Username {
				t.Errorf("List entry username = %q, want %q", got.Username, u.Username)
			}
		}
	}
	if !found {
		t.Error("List did not include the newly created user")
	}
}

func TestStore_Deactivate(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	u := mkUser(t, s, "deactuser")

	if err := s.Deactivate(ctx, u.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	got, err := s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID after deactivate: %v", err)
	}
	if got.DeactivatedAt == nil {
		t.Fatal("expected DeactivatedAt to be set after Deactivate")
	}
}

func TestStore_VerificationTokenLifecycle(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	u := mkUser(t, s, "verifyuser")
	token := "verify-tok-" + uniqueName("")

	if err := s.StoreVerificationToken(ctx, u.ID, token); err != nil {
		t.Fatalf("StoreVerificationToken: %v", err)
	}

	gotUserID, err := s.ConsumeVerificationToken(ctx, token)
	if err != nil {
		t.Fatalf("ConsumeVerificationToken: %v", err)
	}
	if gotUserID != u.ID {
		t.Errorf("ConsumeVerificationToken returned user %q, want %q", gotUserID, u.ID)
	}

	// A used token must not be consumable a second time.
	if _, err := s.ConsumeVerificationToken(ctx, token); err == nil {
		t.Error("expected error consuming an already-used verification token")
	}

	if err := s.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}
	got, err := s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.EmailVerified {
		t.Error("expected EmailVerified=true after MarkEmailVerified")
	}
}

func TestStore_ConsumeVerificationToken_UnknownToken(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	if _, err := s.ConsumeVerificationToken(context.Background(), "no-such-token-"+uniqueName("")); err == nil {
		t.Error("expected error consuming an unknown verification token")
	}
}

func TestStore_PasswordResetTokenLifecycle(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	u := mkUser(t, s, "resetuser")
	token1 := "reset-tok-1-" + uniqueName("")

	if err := s.StorePasswordResetToken(ctx, u.ID, token1); err != nil {
		t.Fatalf("StorePasswordResetToken: %v", err)
	}

	// Requesting a second reset token must invalidate the first (only one
	// live reset token per user at a time) — verified by confirming token1
	// no longer consumes after token2 is issued.
	token2 := "reset-tok-2-" + uniqueName("")
	if err := s.StorePasswordResetToken(ctx, u.ID, token2); err != nil {
		t.Fatalf("StorePasswordResetToken (second): %v", err)
	}

	if _, err := s.ConsumePasswordResetToken(ctx, token1); err == nil {
		t.Error("expected the first reset token to be invalidated once a second was issued")
	}

	gotUserID, err := s.ConsumePasswordResetToken(ctx, token2)
	if err != nil {
		t.Fatalf("ConsumePasswordResetToken (second token): %v", err)
	}
	if gotUserID != u.ID {
		t.Errorf("ConsumePasswordResetToken returned %q, want %q", gotUserID, u.ID)
	}

	// Already used.
	if _, err := s.ConsumePasswordResetToken(ctx, token2); err == nil {
		t.Error("expected error re-consuming an already-used reset token")
	}
}

func TestStore_UpdatePassword(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	u := mkUser(t, s, "updpwuser")
	newHash := "new-hash-" + uniqueName("")

	if err := s.UpdatePassword(ctx, u.ID, newHash); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}

	got, err := s.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.PasswordHash != newHash {
		t.Errorf("PasswordHash after UpdatePassword = %q, want %q", got.PasswordHash, newHash)
	}
}

func TestStore_FindOrCreateBySocial_CreatesNewAccount(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	socialID := uniqueName("google-sub-")
	email := uniqueName("social") + "@example.com"

	u, err := s.FindOrCreateBySocial(ctx, "google", socialID, email, "Social User", "https://avatar.example/pic.png")
	if err != nil {
		t.Fatalf("FindOrCreateBySocial: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	if u.Email != email {
		t.Errorf("created user email = %q, want %q", u.Email, email)
	}
	if !u.EmailVerified {
		t.Error("social sign-up should mark email_verified=true")
	}
	if u.PasswordHash != "" {
		t.Error("social sign-up must not set a password hash")
	}
}

func TestStore_FindOrCreateBySocial_FindsBySocialIDOnSecondCall(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	socialID := uniqueName("google-sub-")
	email := uniqueName("social2") + "@example.com"

	first, err := s.FindOrCreateBySocial(ctx, "google", socialID, email, "Social User", "")
	if err != nil {
		t.Fatalf("FindOrCreateBySocial (create): %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, first.ID) })

	second, err := s.FindOrCreateBySocial(ctx, "google", socialID, "different-email-"+uniqueName("")+"@example.com", "Social User", "")
	if err != nil {
		t.Fatalf("FindOrCreateBySocial (lookup by social id): %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("second call created a new user (id=%q) instead of finding the existing one (id=%q)", second.ID, first.ID)
	}
}

func TestStore_FindOrCreateBySocial_AttachesToExistingEmailMatch(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	// An existing password-based account with this email...
	existing := mkUser(t, s, "preexisting")

	// ...should be found and have the social ID attached rather than a
	// second account being created for the same email address.
	socialID := uniqueName("github-sub-")
	got, err := s.FindOrCreateBySocial(ctx, "github", socialID, existing.Email, "New Display Name", "https://avatar.example/x.png")
	if err != nil {
		t.Fatalf("FindOrCreateBySocial: %v", err)
	}
	if got.ID != existing.ID {
		t.Errorf("FindOrCreateBySocial created/matched a different account (id=%q), want existing account (id=%q)", got.ID, existing.ID)
	}

	var githubID string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(github_id,'') FROM users WHERE id=$1`, existing.ID).Scan(&githubID); err != nil {
		t.Fatalf("query github_id: %v", err)
	}
	if githubID != socialID {
		t.Errorf("github_id = %q, want %q (social login must attach to the pre-existing account by email)", githubID, socialID)
	}
}

func TestStore_FindOrCreateBySocial_UsernameCollisionIsResolved(t *testing.T) {
	pool := testPool(t)
	s := NewStore(pool)
	ctx := context.Background()

	// Create a user whose username is exactly the local-part that
	// sanitizeUsername will derive from the social sign-up email below, to
	// force the ON CONFLICT (username) branch in FindOrCreateBySocial.
	localPart := uniqueName("clash")
	email := localPart + "@example.com"
	existing := &User{Username: localPart, Email: uniqueName("clashowner") + "@example.com"}
	if err := s.Create(ctx, existing); err != nil {
		t.Fatalf("Create (pre-existing username owner): %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, existing.ID) })

	socialID := uniqueName("google-sub-clash-")
	got, err := s.FindOrCreateBySocial(ctx, "google", socialID, email, "Clashing User", "")
	if err != nil {
		t.Fatalf("FindOrCreateBySocial with username collision: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, got.ID) })

	if got.ID == existing.ID {
		t.Fatal("FindOrCreateBySocial must not reuse an unrelated account just because its username collided")
	}
	if got.Username == localPart {
		t.Errorf("expected username collision to be resolved to a different username, got %q", got.Username)
	}
}
