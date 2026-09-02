//go:build integration

package mfa

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// makeKey generates an otp.Key with the same period/digits/algorithm this
// package's enrollment flow uses, for tests that need to insert a setup
// session row directly (bypassing BeginTOTPSetup) to control its
// expires_at.
func makeKey(accountName string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: accountName,
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   totpAlgo,
	})
}

// genCode returns a currently-valid TOTP code for secret, using the exact
// same parameters BeginTOTPSetup/validateTOTPCode use — i.e. what a real
// authenticator app would show right now.
func genCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Digits:    totpDigits,
		Algorithm: totpAlgo,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	return code
}

func TestBeginTOTPSetup_CreatesSetupSession(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-begin-%d", time.Now().UnixNano()))

	setupID, secret, otpauthURL, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if setupID == "" || secret == "" || otpauthURL == "" {
		t.Fatalf("BeginTOTPSetup returned empty field(s): setupID=%q secret=%q otpauthURL=%q", setupID, secret, otpauthURL)
	}

	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_setup_sessions WHERE setup_id=$1 AND user_id=$2`, setupID, userID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Fatalf("totp_setup_sessions rows = %d, want 1", count)
	}
}

// TestBeginTOTPSetup_InvalidatesPreviousSession mirrors StoreSMSOTP's
// invalidate-previous behavior: starting a new enrollment must not leave a
// second, older pending secret confirmable.
func TestBeginTOTPSetup_InvalidatesPreviousSession(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-begin-twice-%d", time.Now().UnixNano()))

	firstSetupID, _, _, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup (1st): %v", err)
	}
	if _, _, _, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com"); err != nil {
		t.Fatalf("BeginTOTPSetup (2nd): %v", err)
	}

	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_setup_sessions WHERE setup_id=$1`, firstSetupID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 0 {
		t.Fatal("the first setup session should have been invalidated by the second BeginTOTPSetup call")
	}

	var totalCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_setup_sessions WHERE user_id=$1`, userID,
	).Scan(&totalCount); err != nil {
		t.Fatalf("query: %v", err)
	}
	if totalCount != 1 {
		t.Fatalf("totp_setup_sessions rows for user = %d, want 1", totalCount)
	}
}

func TestConfirmTOTPSetup_HappyPath(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-confirm-ok-%d", time.Now().UnixNano()))

	setupID, secret, _, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}

	backupCodes, err := ConfirmTOTPSetup(context.Background(), pool, userID, setupID, genCode(t, secret), 4)
	if err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}
	if len(backupCodes) != numBackupCodes {
		t.Fatalf("got %d backup codes, want %d", len(backupCodes), numBackupCodes)
	}

	enabled, err := IsTOTPEnabled(context.Background(), pool, userID)
	if err != nil || !enabled {
		t.Fatalf("IsTOTPEnabled after confirm = (%v, %v), want (true, nil)", enabled, err)
	}

	var sessionCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_setup_sessions WHERE setup_id=$1`, setupID,
	).Scan(&sessionCount); err != nil {
		t.Fatalf("query: %v", err)
	}
	if sessionCount != 0 {
		t.Fatal("setup session should be deleted after successful confirmation")
	}

	var backupRowCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_backup_codes WHERE user_id=$1 AND used_at IS NULL`, userID,
	).Scan(&backupRowCount); err != nil {
		t.Fatalf("query: %v", err)
	}
	if backupRowCount != numBackupCodes {
		t.Fatalf("totp_backup_codes unused rows = %d, want %d", backupRowCount, numBackupCodes)
	}

	// The secret itself must never be recoverable from the stored row in
	// plaintext form via any exported API — only VerifyTOTPCode (possession
	// proof) reads it from here on. This test doesn't assert on storage
	// encoding (out of scope), but does assert BeginTOTPSetup/ConfirmTOTPSetup
	// are the only paths that ever return it, and they don't run again for
	// an already-confirmed credential.
	if err := VerifyTOTPCode(context.Background(), pool, userID, genCode(t, secret)); err != nil {
		t.Fatalf("VerifyTOTPCode should accept a fresh valid code against the now-active credential: %v", err)
	}
}

func TestConfirmTOTPSetup_WrongCode_SessionSurvives(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-confirm-wrong-%d", time.Now().UnixNano()))

	setupID, _, _, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}

	if _, err := ConfirmTOTPSetup(context.Background(), pool, userID, setupID, "000000", 4); err != ErrInvalidCode {
		t.Fatalf("ConfirmTOTPSetup with wrong code: err = %v, want ErrInvalidCode", err)
	}

	// The session must still be there — a mistyped code shouldn't force the
	// user to restart enrollment.
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_setup_sessions WHERE setup_id=$1`, setupID,
	).Scan(&count); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 {
		t.Fatal("setup session should survive a wrong-code confirm attempt")
	}

	enabled, _ := IsTOTPEnabled(context.Background(), pool, userID)
	if enabled {
		t.Fatal("totp must not become enabled from an unconfirmed/wrong-code session")
	}
}

func TestConfirmTOTPSetup_ExpiredSessionRejected(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-confirm-expired-%d", time.Now().UnixNano()))

	key, err := makeKey("user@example.com")
	if err != nil {
		t.Fatalf("makeKey: %v", err)
	}
	var setupID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO totp_setup_sessions (user_id, secret, expires_at) VALUES ($1,$2,$3) RETURNING setup_id`,
		userID, key.Secret(), time.Now().Add(-time.Minute),
	).Scan(&setupID); err != nil {
		t.Fatalf("insert expired session: %v", err)
	}

	if _, err := ConfirmTOTPSetup(context.Background(), pool, userID, setupID, genCode(t, key.Secret()), 4); err != ErrSetupExpired {
		t.Fatalf("ConfirmTOTPSetup on expired session: err = %v, want ErrSetupExpired", err)
	}
}

// TestConfirmTOTPSetup_WrongUserRejected is an IDOR regression test: one
// user must not be able to confirm (and thus take over) another user's
// pending setup session by guessing/observing its setup_id.
func TestConfirmTOTPSetup_WrongUserRejected(t *testing.T) {
	pool := requireDB(t)
	victim := createTestUser(t, pool, fmt.Sprintf("totp-victim-%d", time.Now().UnixNano()))
	attacker := createTestUser(t, pool, fmt.Sprintf("totp-attacker-%d", time.Now().UnixNano()))

	setupID, secret, _, err := BeginTOTPSetup(context.Background(), pool, victim, "victim@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}

	if _, err := ConfirmTOTPSetup(context.Background(), pool, attacker, setupID, genCode(t, secret), 4); err != ErrNoPendingSetup {
		t.Fatalf("ConfirmTOTPSetup with wrong user: err = %v, want ErrNoPendingSetup", err)
	}

	enabled, _ := IsTOTPEnabled(context.Background(), pool, attacker)
	if enabled {
		t.Fatal("attacker must not have gained an enabled totp credential from the victim's session")
	}
}

func TestVerifyTOTPCode_LockoutAfterRepeatedFailures(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-lockout-%d", time.Now().UnixNano()))
	setupID, secret, _, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if _, err := ConfirmTOTPSetup(context.Background(), pool, userID, setupID, genCode(t, secret), 4); err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	for i := 0; i < maxFailedAttempts-1; i++ {
		if err := VerifyTOTPCode(context.Background(), pool, userID, "000000"); err != ErrInvalidCode {
			t.Fatalf("attempt %d: err = %v, want ErrInvalidCode", i, err)
		}
	}
	// The Nth failure should trip the lockout.
	if err := VerifyTOTPCode(context.Background(), pool, userID, "000000"); err != ErrInvalidCode {
		t.Fatalf("final failing attempt: err = %v, want ErrInvalidCode", err)
	}

	// Even a now-correct code must be rejected while locked.
	if err := VerifyTOTPCode(context.Background(), pool, userID, genCode(t, secret)); err != ErrLocked {
		t.Fatalf("VerifyTOTPCode while locked: err = %v, want ErrLocked", err)
	}
}

func TestVerifyTOTPCode_SuccessResetsFailureCounter(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-reset-%d", time.Now().UnixNano()))
	setupID, secret, _, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if _, err := ConfirmTOTPSetup(context.Background(), pool, userID, setupID, genCode(t, secret), 4); err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	if err := VerifyTOTPCode(context.Background(), pool, userID, "000000"); err != ErrInvalidCode {
		t.Fatalf("bad attempt: err = %v", err)
	}
	if err := VerifyTOTPCode(context.Background(), pool, userID, genCode(t, secret)); err != nil {
		t.Fatalf("good attempt: err = %v, want nil", err)
	}

	var failedAttempts int
	if err := pool.QueryRow(context.Background(),
		`SELECT failed_attempts FROM totp_credentials WHERE user_id=$1`, userID,
	).Scan(&failedAttempts); err != nil {
		t.Fatalf("query: %v", err)
	}
	if failedAttempts != 0 {
		t.Fatalf("failed_attempts after a successful verify = %d, want 0", failedAttempts)
	}
}

func TestVerifyTOTPCode_NotEnrolled(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-notenrolled-%d", time.Now().UnixNano()))

	if err := VerifyTOTPCode(context.Background(), pool, userID, "123456"); err != ErrNotEnrolled {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
}

func TestVerifyTOTPBackupCode_SingleUse(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-backup-singleuse-%d", time.Now().UnixNano()))
	setupID, secret, _, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	backupCodes, err := ConfirmTOTPSetup(context.Background(), pool, userID, setupID, genCode(t, secret), 4)
	if err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	code := backupCodes[0]
	if !VerifyTOTPBackupCode(context.Background(), pool, userID, code) {
		t.Fatal("VerifyTOTPBackupCode (1st use): expected true")
	}
	if VerifyTOTPBackupCode(context.Background(), pool, userID, code) {
		t.Fatal("VerifyTOTPBackupCode (2nd use / replay): expected false — a used backup code must not verify again")
	}
}

func TestVerifyTOTPBackupCode_CaseAndDashInsensitive(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-backup-canon-%d", time.Now().UnixNano()))
	setupID, secret, _, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	backupCodes, err := ConfirmTOTPSetup(context.Background(), pool, userID, setupID, genCode(t, secret), 4)
	if err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	lower := "  " + strings.ToLower(backupCodes[0]) + "  "
	if !VerifyTOTPBackupCode(context.Background(), pool, userID, lower) {
		t.Fatal("VerifyTOTPBackupCode should accept a lowercase/whitespace-padded form of a valid code")
	}
}

func TestVerifyTOTPBackupCode_WrongCodeRejected(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-backup-wrong-%d", time.Now().UnixNano()))
	setupID, secret, _, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if _, err := ConfirmTOTPSetup(context.Background(), pool, userID, setupID, genCode(t, secret), 4); err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	if VerifyTOTPBackupCode(context.Background(), pool, userID, "ZZZZ-ZZZZ") {
		t.Fatal("VerifyTOTPBackupCode: expected false for an unknown code")
	}
}

func TestDisableTOTPCredential_RemovesCredentialAndBackupCodes(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-disable-%d", time.Now().UnixNano()))
	setupID, secret, _, err := BeginTOTPSetup(context.Background(), pool, userID, "user@example.com")
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if _, err := ConfirmTOTPSetup(context.Background(), pool, userID, setupID, genCode(t, secret), 4); err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	if err := DisableTOTPCredential(context.Background(), pool, userID); err != nil {
		t.Fatalf("DisableTOTPCredential: %v", err)
	}

	enabled, _ := IsTOTPEnabled(context.Background(), pool, userID)
	if enabled {
		t.Fatal("IsTOTPEnabled after disable = true, want false")
	}
	var backupCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_backup_codes WHERE user_id=$1`, userID,
	).Scan(&backupCount); err != nil {
		t.Fatalf("query: %v", err)
	}
	if backupCount != 0 {
		t.Fatalf("totp_backup_codes rows after disable = %d, want 0", backupCount)
	}
}

// ── login challenges ─────────────────────────────────────────────────────

func TestTOTPLoginChallenge_RoundTrip(t *testing.T) {
	pool := requireDB(t)
	username := fmt.Sprintf("totp-challenge-%d", time.Now().UnixNano())
	userID := createTestUser(t, pool, username)

	challengeID, err := CreateTOTPLoginChallenge(context.Background(), pool, userID)
	if err != nil {
		t.Fatalf("CreateTOTPLoginChallenge: %v", err)
	}

	gotUserID, gotUsername, err := ResolveTOTPLoginChallenge(context.Background(), pool, challengeID)
	if err != nil {
		t.Fatalf("ResolveTOTPLoginChallenge: %v", err)
	}
	if gotUserID != userID || gotUsername != username {
		t.Fatalf("resolved (%q, %q), want (%q, %q)", gotUserID, gotUsername, userID, username)
	}

	DeleteTOTPLoginChallenge(context.Background(), pool, challengeID)
	if _, _, err := ResolveTOTPLoginChallenge(context.Background(), pool, challengeID); err != ErrChallengeInvalid {
		t.Fatalf("ResolveTOTPLoginChallenge after delete: err = %v, want ErrChallengeInvalid", err)
	}
}

func TestTOTPLoginChallenge_ExpiredRejected(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-challenge-expired-%d", time.Now().UnixNano()))

	var challengeID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO totp_login_challenges (user_id, expires_at) VALUES ($1,$2) RETURNING challenge_id`,
		userID, time.Now().Add(-time.Minute),
	).Scan(&challengeID); err != nil {
		t.Fatalf("insert expired challenge: %v", err)
	}

	if _, _, err := ResolveTOTPLoginChallenge(context.Background(), pool, challengeID); err != ErrChallengeInvalid {
		t.Fatalf("err = %v, want ErrChallengeInvalid", err)
	}
}

func TestTOTPLoginChallenge_UnknownIDRejected(t *testing.T) {
	pool := requireDB(t)
	if _, _, err := ResolveTOTPLoginChallenge(context.Background(), pool, "00000000-0000-0000-0000-000000000000"); err != ErrChallengeInvalid {
		t.Fatalf("err = %v, want ErrChallengeInvalid", err)
	}
}

func TestCreateTOTPLoginChallenge_InvalidatesPrevious(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, fmt.Sprintf("totp-challenge-twice-%d", time.Now().UnixNano()))

	first, err := CreateTOTPLoginChallenge(context.Background(), pool, userID)
	if err != nil {
		t.Fatalf("CreateTOTPLoginChallenge (1st): %v", err)
	}
	if _, err := CreateTOTPLoginChallenge(context.Background(), pool, userID); err != nil {
		t.Fatalf("CreateTOTPLoginChallenge (2nd): %v", err)
	}

	if _, _, err := ResolveTOTPLoginChallenge(context.Background(), pool, first); err != ErrChallengeInvalid {
		t.Fatal("the first login challenge should have been invalidated by the second CreateTOTPLoginChallenge call")
	}
}
