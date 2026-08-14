//go:build integration

package user

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// The bcrypt cost used across this test file. Kept low (bcrypt.MinCost) so
// the integration suite runs quickly — correctness of the hashing scheme
// does not depend on the cost factor.
const testBcryptCost = bcrypt.MinCost

func newTestService(t *testing.T) *Service {
	t.Helper()
	pool := testPool(t)
	return NewService(NewStore(pool), testBcryptCost)
}

func TestService_HashPassword_NeverStoresPlaintext(t *testing.T) {
	svc := newTestService(t)
	password := "correct horse battery staple"

	hash, err := svc.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == password {
		t.Fatal("HashPassword returned the plaintext password unchanged")
	}
	if strings.Contains(hash, password) {
		t.Fatal("hash must not contain the plaintext password as a substring")
	}
	// A bcrypt hash must itself validate against the password it was
	// derived from — this is the property Authenticate relies on.
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		t.Fatalf("bcrypt hash does not validate against its own password: %v", err)
	}
}

func TestService_HashPassword_SaltedNotDeterministic(t *testing.T) {
	svc := newTestService(t)
	h1, err := svc.HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	h2, err := svc.HashPassword("same-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if h1 == h2 {
		t.Fatal("hashing the same password twice produced identical hashes — bcrypt salt is not being randomized")
	}
}

func TestService_Create_PersistsHashedPasswordOnly(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	username := uniqueName("createsvc")
	password := "a-reasonably-strong-password-1"

	u, err := svc.Create(ctx, username, username+"@example.com", password, "Display Name")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.store.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	if u.PasswordHash == password {
		t.Fatal("Service.Create stored the plaintext password as the hash")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		t.Fatalf("stored hash does not validate against the original password: %v", err)
	}

	// Round-trip through the store: the raw DB row must not contain the
	// plaintext password anywhere.
	stored, err := svc.store.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if stored.PasswordHash == password {
		t.Fatal("plaintext password persisted to the users table")
	}
}

func TestService_Create_Duplicate(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	username := uniqueName("dupsvc")

	u1, err := svc.Create(ctx, username, username+"@example.com", "password1", "First")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.store.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u1.ID) })

	if _, err := svc.Create(ctx, username, uniqueName("other")+"@example.com", "password2", "Second"); err != ErrDuplicate {
		t.Fatalf("Create with duplicate username = %v, want ErrDuplicate", err)
	}
}

func TestService_Authenticate_Success(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	username := uniqueName("authok")
	password := "hunter2-but-longer"

	u, err := svc.Create(ctx, username, username+"@example.com", password, "Auth User")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.store.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	got, err := svc.Authenticate(ctx, username, password)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("Authenticate returned user %q, want %q", got.ID, u.ID)
	}
}

func TestService_Authenticate_ByEmailIdentifier(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	username := uniqueName("authemail")
	password := "another-long-password"

	u, err := svc.Create(ctx, username, username+"@example.com", password, "Auth User")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.store.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	// Login form submits the email address in the username field.
	got, err := svc.Authenticate(ctx, u.Email, password)
	if err != nil {
		t.Fatalf("Authenticate by email: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("Authenticate by email returned user %q, want %q", got.ID, u.ID)
	}
}

func TestService_Authenticate_WrongPassword(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	username := uniqueName("authbad")

	u, err := svc.Create(ctx, username, username+"@example.com", "correct-password", "Auth User")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.store.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	if _, err := svc.Authenticate(ctx, username, "totally-wrong-password"); err != ErrBadPassword {
		t.Fatalf("Authenticate with wrong password = %v, want ErrBadPassword", err)
	}
}

func TestService_Authenticate_UnknownUser(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.Authenticate(context.Background(), "no-such-user-"+uniqueName(""), "whatever"); err != ErrBadPassword {
		t.Fatalf("Authenticate for unknown user = %v, want ErrBadPassword (must not leak whether the account exists)", err)
	}
}

func TestService_Authenticate_UnknownEmail(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.Authenticate(context.Background(), "no-such-"+uniqueName("")+"@example.com", "whatever"); err != ErrBadPassword {
		t.Fatalf("Authenticate for unknown email = %v, want ErrBadPassword", err)
	}
}

func TestService_Authenticate_DeactivatedAccount(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	username := uniqueName("authdeact")
	password := "some-password-value"

	u, err := svc.Create(ctx, username, username+"@example.com", password, "Auth User")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.store.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	if err := svc.Deactivate(ctx, u.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	_, err = svc.Authenticate(ctx, username, password)
	if err == nil {
		t.Fatal("expected Authenticate to reject a deactivated account even with the correct password")
	}
	if err == ErrBadPassword {
		t.Error("deactivated-account error should be distinguishable from a bad password, not ErrBadPassword")
	}
}

func TestService_GenerateToken_ReturnsUniqueHexTokens(t *testing.T) {
	svc := newTestService(t)
	t1, err := svc.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	t2, err := svc.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if t1 == t2 {
		t.Fatal("GenerateToken produced identical tokens on consecutive calls")
	}
	if len(t1) != 64 { // 32 random bytes, hex-encoded
		t.Errorf("GenerateToken length = %d, want 64 (32 bytes hex-encoded)", len(t1))
	}
}

func TestService_PlatformAdmin_PromoteAndCheck(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	username := uniqueName("svcadmin")
	email := username + "@example.com"

	u, err := svc.Create(ctx, username, email, "password-value", "Admin User")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.store.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	isAdmin, err := svc.IsPlatformAdmin(ctx, u.ID)
	if err != nil {
		t.Fatalf("IsPlatformAdmin: %v", err)
	}
	if isAdmin {
		t.Fatal("new user should not default to platform-admin")
	}

	found, err := svc.SetPlatformAdmin(ctx, email, true)
	if err != nil || !found {
		t.Fatalf("SetPlatformAdmin: found=%v err=%v", found, err)
	}

	isAdmin, err = svc.IsPlatformAdmin(ctx, u.ID)
	if err != nil {
		t.Fatalf("IsPlatformAdmin after promote: %v", err)
	}
	if !isAdmin {
		t.Fatal("expected platform-admin after SetPlatformAdmin(true)")
	}
}

func TestService_VerificationAndPasswordResetTokenFlows(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	username := uniqueName("svctok")

	u, err := svc.Create(ctx, username, username+"@example.com", "password-value", "Token User")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.store.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	verifyTok, err := svc.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := svc.StoreVerificationToken(ctx, u.ID, verifyTok); err != nil {
		t.Fatalf("StoreVerificationToken: %v", err)
	}
	gotID, err := svc.ConsumeVerificationToken(ctx, verifyTok)
	if err != nil || gotID != u.ID {
		t.Fatalf("ConsumeVerificationToken: id=%q err=%v", gotID, err)
	}
	if err := svc.MarkEmailVerified(ctx, u.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}
	got, err := svc.GetByID(ctx, u.ID)
	if err != nil || !got.EmailVerified {
		t.Fatalf("expected EmailVerified=true, got %+v err=%v", got, err)
	}

	resetTok, err := svc.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := svc.StorePasswordResetToken(ctx, u.ID, resetTok); err != nil {
		t.Fatalf("StorePasswordResetToken: %v", err)
	}
	gotID, err = svc.ConsumePasswordResetToken(ctx, resetTok)
	if err != nil || gotID != u.ID {
		t.Fatalf("ConsumePasswordResetToken: id=%q err=%v", gotID, err)
	}

	newHash, err := svc.HashPassword("brand-new-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := svc.UpdatePassword(ctx, u.ID, newHash); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}

	// The new password must now authenticate and the old one must not.
	if _, err := svc.Authenticate(ctx, username, "brand-new-password"); err != nil {
		t.Fatalf("Authenticate with new password: %v", err)
	}
	if _, err := svc.Authenticate(ctx, username, "password-value"); err != ErrBadPassword {
		t.Fatalf("Authenticate with old password after reset = %v, want ErrBadPassword", err)
	}
}

// TestService_Create_DoesNotRejectWeakOrEmptyPasswords documents a real gap
// rather than asserting desired behavior: internal/user.Service.Create has
// no password-strength or minimum-length validation at all — it hashes and
// stores whatever string is handed to it, including "". If no caller
// upstream (e.g. the registration HTTP handler, outside this package's
// scope) enforces a minimum, an account can be created with an empty or
// trivially guessable password. This test pins the current behavior so a
// future change to add validation here is a deliberate, visible diff rather
// than an untested one.
func TestService_Create_DoesNotRejectWeakOrEmptyPasswords(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	username := uniqueName("weakpw")

	u, err := svc.Create(ctx, username, username+"@example.com", "", "Weak Password User")
	if err != nil {
		t.Fatalf("Create with empty password unexpectedly failed with %v (if validation was added, update this test to assert the specific rejection error instead)", err)
	}
	t.Cleanup(func() { _, _ = svc.store.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	// An empty password still authenticates, since it was hashed and stored
	// like any other value — confirming the store layer has no independent
	// guard either.
	if _, err := svc.Authenticate(ctx, username, ""); err != nil {
		t.Fatalf("Authenticate with the empty password that was set at Create time: %v", err)
	}
}

func TestService_FindOrCreateBySocial(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	email := uniqueName("svcsocial") + "@example.com"

	u, err := svc.FindOrCreateBySocial(ctx, "google", uniqueName("sub"), email, "Social", "")
	if err != nil {
		t.Fatalf("FindOrCreateBySocial: %v", err)
	}
	t.Cleanup(func() { _, _ = svc.store.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	if u.Email != email {
		t.Errorf("Email = %q, want %q", u.Email, email)
	}
}
