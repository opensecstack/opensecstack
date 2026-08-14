//go:build integration

package mfa

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// requireDB skips the test when SINAUTH_TEST_DB_URL is unset, mirroring the
// integration-test gating pattern used elsewhere in sinauth (see
// internal/organization/store_test.go, internal/rbac/store_test.go).
func requireDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("SINAUTH_TEST_DB_URL")
	if url == "" {
		t.Skip("SINAUTH_TEST_DB_URL not set — skipping mfa store integration test")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func createTestUser(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id`,
		username, username+"@example.com",
	).Scan(&id)
	if err != nil {
		t.Fatalf("createTestUser: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, id) })
	return id
}

func TestStoreAndVerifySMSOTP_HappyPath(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "sms-otp-happy")

	if err := StoreSMSOTP(context.Background(), pool, userID, "+15551234567", "123456"); err != nil {
		t.Fatalf("StoreSMSOTP: %v", err)
	}

	if ok := VerifySMSOTP(context.Background(), pool, userID, "123456"); !ok {
		t.Fatal("VerifySMSOTP: expected true for correct, unused, unexpired code")
	}
}

// TestVerifySMSOTP_ReplayIsRejected is a replay-protection test: once a code
// has been successfully verified, using the same code again for the same
// user must fail. VerifySMSOTP marks the row used=true on success; this
// proves that flag is actually enforced by the WHERE clause on the next
// lookup, not just recorded for audit purposes.
func TestVerifySMSOTP_ReplayIsRejected(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "sms-otp-replay")

	if err := StoreSMSOTP(context.Background(), pool, userID, "+15551234567", "654321"); err != nil {
		t.Fatalf("StoreSMSOTP: %v", err)
	}

	if ok := VerifySMSOTP(context.Background(), pool, userID, "654321"); !ok {
		t.Fatal("VerifySMSOTP (1st use): expected true")
	}
	if ok := VerifySMSOTP(context.Background(), pool, userID, "654321"); ok {
		t.Fatal("VerifySMSOTP (2nd use / replay): expected false — a used code must not verify again")
	}
}

// TestVerifySMSOTP_WrongCodeRejected proves an incorrect code for a user
// with a valid pending OTP does not verify.
func TestVerifySMSOTP_WrongCodeRejected(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "sms-otp-wrongcode")

	if err := StoreSMSOTP(context.Background(), pool, userID, "+15551234567", "111111"); err != nil {
		t.Fatalf("StoreSMSOTP: %v", err)
	}

	if ok := VerifySMSOTP(context.Background(), pool, userID, "999999"); ok {
		t.Fatal("VerifySMSOTP: expected false for wrong code")
	}
	// The correct code must still be usable afterwards — a failed guess
	// should not burn the legitimate code.
	if ok := VerifySMSOTP(context.Background(), pool, userID, "111111"); !ok {
		t.Fatal("VerifySMSOTP: correct code should still verify after an unrelated wrong guess")
	}
}

// TestVerifySMSOTP_ExpiredCodeRejected proves a code past its expires_at is
// rejected even though it was never used — an attacker who obtains a stale
// code (e.g. from a log or intercepted SMS) after its validity window must
// not be able to use it.
func TestVerifySMSOTP_ExpiredCodeRejected(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "sms-otp-expired")

	// Insert directly with an already-past expires_at, since StoreSMSOTP
	// always uses the table default (+10 minutes from now).
	_, err := pool.Exec(context.Background(),
		`INSERT INTO sms_otp (user_id, phone, code, expires_at) VALUES ($1,$2,$3,$4)`,
		userID, "+15551234567", "222222", time.Now().Add(-time.Minute),
	)
	if err != nil {
		t.Fatalf("insert expired otp: %v", err)
	}

	if ok := VerifySMSOTP(context.Background(), pool, userID, "222222"); ok {
		t.Fatal("VerifySMSOTP: expected false for expired code")
	}
}

// TestStoreSMSOTP_InvalidatesPreviousCode proves that requesting a new OTP
// invalidates any previously issued, still-unused code for that user — so
// only the newest code sent to the user's phone is ever valid, and a leaked
// older code can't be verified after a newer one was requested.
func TestStoreSMSOTP_InvalidatesPreviousCode(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "sms-otp-invalidate")

	if err := StoreSMSOTP(context.Background(), pool, userID, "+15551234567", "333333"); err != nil {
		t.Fatalf("StoreSMSOTP (1st): %v", err)
	}
	if err := StoreSMSOTP(context.Background(), pool, userID, "+15551234567", "444444"); err != nil {
		t.Fatalf("StoreSMSOTP (2nd): %v", err)
	}

	if ok := VerifySMSOTP(context.Background(), pool, userID, "333333"); ok {
		t.Fatal("VerifySMSOTP: the old code should have been invalidated by the new StoreSMSOTP call")
	}
	if ok := VerifySMSOTP(context.Background(), pool, userID, "444444"); !ok {
		t.Fatal("VerifySMSOTP: the newest code should still verify")
	}
}

// TestVerifySMSOTP_WrongUserRejected proves a valid code issued to one user
// cannot be verified under a different user's id — the WHERE clause must
// scope by user_id, not just code value.
func TestVerifySMSOTP_WrongUserRejected(t *testing.T) {
	pool := requireDB(t)
	userA := createTestUser(t, pool, "sms-otp-usera")
	userB := createTestUser(t, pool, "sms-otp-userb")

	if err := StoreSMSOTP(context.Background(), pool, userA, "+15551234567", "555555"); err != nil {
		t.Fatalf("StoreSMSOTP: %v", err)
	}

	if ok := VerifySMSOTP(context.Background(), pool, userB, "555555"); ok {
		t.Fatal("VerifySMSOTP: code issued to userA must not verify for userB")
	}
}
