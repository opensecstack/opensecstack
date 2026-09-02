// Package mfa: TOTP (RFC 6238) second-factor authentication.
//
// The schema (migrations/007_totp.sql, migrations/020_totp_backup_codes.sql)
// predates this file: totp_credentials/totp_setup_sessions existed with zero
// Go code reading or writing them. This file is the real implementation —
// secret generation and code validation are delegated entirely to
// github.com/pquerna/otp (an RFC 6238-compliant library), never hand-rolled.
//
// Enrollment is two-step by design, matching totp_setup_sessions' 10-minute
// TTL: BeginTOTPSetup generates a secret and parks it as a *pending* setup
// session; ConfirmTOTPSetup only promotes it into an active totp_credentials
// row (enabled=true) once the caller proves they actually captured the
// secret by producing a valid code from it. The secret is never returned to
// the client again after that point — only code verification proves
// possession from then on.
package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	totpIssuer = "SIN"
	totpPeriod = 30 // seconds per RFC 6238's standard time-step
	totpSkew   = 1  // ± 1 period (30s) clock-skew allowance — not an "anything goes" window
	totpDigits = otp.DigitsSix
	totpAlgo   = otp.AlgorithmSHA1

	maxFailedAttempts = 5
	lockoutDuration   = 15 * time.Minute

	numBackupCodes  = 10
	backupCodeBytes = 5 // 40 bits -> 8 base32 chars
)

var (
	ErrNoPendingSetup   = errors.New("mfa: no pending totp setup session for this user")
	ErrSetupExpired     = errors.New("mfa: totp setup session expired")
	ErrInvalidCode      = errors.New("mfa: invalid totp code")
	ErrLocked           = errors.New("mfa: totp verification locked due to repeated failed attempts")
	ErrNotEnrolled      = errors.New("mfa: totp is not enabled for this user")
	ErrChallengeInvalid = errors.New("mfa: invalid or expired totp login challenge")
)

// BeginTOTPSetup generates a fresh TOTP secret and stores it as a pending
// totp_setup_sessions row (10-minute TTL, per the table default). Any
// previous pending session for this user is invalidated first — mirroring
// StoreSMSOTP's "only the newest pending credential is valid" pattern —
// so an abandoned enrollment attempt can't be confirmed later against a
// stale secret the user never actually scanned.
//
// Returns the setup session id, the base32 secret (shown once, for manual
// entry), and the otpauth:// URI (for QR-code rendering by the client —
// sinauth has no QR-image-generation dependency in go.mod, so the URI is
// returned for the client to render, same as most TOTP-enrollment APIs).
func BeginTOTPSetup(ctx context.Context, pool *pgxpool.Pool, userID, accountName string) (setupID, secret, otpauthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: accountName,
		Period:      totpPeriod,
		Digits:      totpDigits,
		Algorithm:   totpAlgo,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("mfa: generate totp secret: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM totp_setup_sessions WHERE user_id=$1`, userID); err != nil {
		return "", "", "", err
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO totp_setup_sessions (user_id, secret) VALUES ($1, $2) RETURNING setup_id`,
		userID, key.Secret(),
	).Scan(&setupID); err != nil {
		return "", "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", "", err
	}

	return setupID, key.Secret(), key.String(), nil
}

// ConfirmTOTPSetup validates a 6-digit code against the pending setup
// session's secret and, on success, atomically promotes it into an active
// totp_credentials row and generates a fresh set of backup codes. On
// failure the pending session is left intact (unless expired) so the user
// can retry a mistyped code within the original 10-minute window rather
// than being forced to restart enrollment from scratch.
//
// userID scopes the lookup so one user can never confirm (and thus hijack)
// another user's pending setup session by guessing/observing its id.
//
// Returns the plaintext backup codes exactly once — callers must display
// them to the user immediately; they are never retrievable again (only
// their bcrypt hashes are persisted).
func ConfirmTOTPSetup(ctx context.Context, pool *pgxpool.Pool, userID, setupID, code string, bcryptCost int) ([]string, error) {
	var secret string
	var expiresAt time.Time
	err := pool.QueryRow(ctx,
		`SELECT secret, expires_at FROM totp_setup_sessions WHERE setup_id=$1 AND user_id=$2`,
		setupID, userID,
	).Scan(&secret, &expiresAt)
	if err != nil {
		return nil, ErrNoPendingSetup
	}
	if time.Now().After(expiresAt) {
		// Clean up the stale session so it can't be confirmed later even if
		// this check were somehow bypassed, and so BeginTOTPSetup's
		// invalidate-previous DELETE has nothing stale to race against.
		_, _ = pool.Exec(ctx, `DELETE FROM totp_setup_sessions WHERE setup_id=$1`, setupID)
		return nil, ErrSetupExpired
	}
	if !validateTOTPCode(secret, code) {
		return nil, ErrInvalidCode
	}

	backupCodes, hashes, err := generateBackupCodes(bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("mfa: generate backup codes: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO totp_credentials (user_id, secret, enabled, failed_attempts, locked_until)
		 VALUES ($1, $2, true, 0, NULL)
		 ON CONFLICT (user_id) DO UPDATE SET
		     secret=EXCLUDED.secret, enabled=true, failed_attempts=0, locked_until=NULL`,
		userID, secret,
	); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM totp_setup_sessions WHERE setup_id=$1`, setupID); err != nil {
		return nil, err
	}
	// Replace any backup codes from a prior enrollment — re-enrolling (e.g.
	// after losing the authenticator) must invalidate old recovery codes,
	// not accumulate two valid sets.
	if _, err := tx.Exec(ctx, `DELETE FROM totp_backup_codes WHERE user_id=$1`, userID); err != nil {
		return nil, err
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO totp_backup_codes (user_id, code_hash) VALUES ($1, $2)`,
			userID, h,
		); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return backupCodes, nil
}

// IsTOTPEnabled reports whether the user has a confirmed, active TOTP
// credential — used by the login handler to decide whether password auth
// alone is sufficient or a step-up challenge is required.
//
// Only pgx.ErrNoRows (genuinely "not enrolled") is folded into (false, nil).
// Any other error (a real connection/query failure) is propagated so the
// caller fails the login attempt instead of silently treating a DB hiccup
// as "MFA not required" — the caller (handlers.Login) already has an
// err != nil check for exactly this, which this used to defeat by never
// actually returning a non-nil error.
func IsTOTPEnabled(ctx context.Context, pool *pgxpool.Pool, userID string) (bool, error) {
	var enabled bool
	err := pool.QueryRow(ctx,
		`SELECT enabled FROM totp_credentials WHERE user_id=$1`, userID,
	).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("mfa: check totp enrollment: %w", err)
	}
	return enabled, nil
}

// VerifyTOTPCode checks a 6-digit code against the user's active credential,
// enforcing a lockout after maxFailedAttempts consecutive failures so a
// TOTP code (only 10^6 possibilities) can't be brute-forced online. A
// successful verification resets the failure counter.
func VerifyTOTPCode(ctx context.Context, pool *pgxpool.Pool, userID, code string) error {
	var secret string
	var enabled bool
	var failedAttempts int
	var lockedUntil *time.Time
	err := pool.QueryRow(ctx,
		`SELECT secret, enabled, failed_attempts, locked_until FROM totp_credentials WHERE user_id=$1`,
		userID,
	).Scan(&secret, &enabled, &failedAttempts, &lockedUntil)
	if err != nil || !enabled {
		return ErrNotEnrolled
	}
	if lockedUntil != nil && time.Now().Before(*lockedUntil) {
		return ErrLocked
	}

	if !validateTOTPCode(secret, code) {
		failedAttempts++
		var newLock *time.Time
		if failedAttempts >= maxFailedAttempts {
			t := time.Now().Add(lockoutDuration)
			newLock = &t
			failedAttempts = 0 // counter resets once the lockout itself takes over
		}
		// Best-effort: a failure to persist the incremented counter must not
		// be reported as a successful verification (the caller only sees
		// ErrInvalidCode either way), but we still try to record it so the
		// lockout stays accurate.
		_, _ = pool.Exec(ctx,
			`UPDATE totp_credentials SET failed_attempts=$1, locked_until=$2 WHERE user_id=$3`,
			failedAttempts, newLock, userID,
		)
		return ErrInvalidCode
	}

	if _, err := pool.Exec(ctx,
		`UPDATE totp_credentials SET failed_attempts=0, locked_until=NULL WHERE user_id=$1`,
		userID,
	); err != nil {
		return fmt.Errorf("mfa: reset totp failure counter: %w", err)
	}
	return nil
}

// VerifyTOTPBackupCode checks a single-use recovery code and marks it
// consumed on success. Returns false for any invalid, already-used, or
// unknown code — including when the user has no TOTP credential at all.
func VerifyTOTPBackupCode(ctx context.Context, pool *pgxpool.Pool, userID, code string) bool {
	canonical := canonicalizeBackupCode(code)
	if canonical == "" {
		return false
	}

	rows, err := pool.Query(ctx,
		`SELECT id, code_hash FROM totp_backup_codes WHERE user_id=$1 AND used_at IS NULL`,
		userID,
	)
	if err != nil {
		return false
	}
	defer rows.Close()

	var matchID string
	for rows.Next() {
		var id, hash string
		if err := rows.Scan(&id, &hash); err != nil {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(canonical)) == nil {
			matchID = id
			break
		}
	}
	if err := rows.Err(); err != nil {
		return false
	}
	if matchID == "" {
		return false
	}

	// Marking-used failure must not be treated as a successful verification —
	// otherwise the same backup code stays usable (used_at still NULL) and
	// replayable, exactly the bug UpdateCredential's sibling comment on the
	// SMS OTP path warns about.
	tag, err := pool.Exec(ctx,
		`UPDATE totp_backup_codes SET used_at=now() WHERE id=$1 AND used_at IS NULL`,
		matchID,
	)
	if err != nil || tag.RowsAffected() != 1 {
		return false
	}
	return true
}

// DisableTOTPCredential removes the user's active TOTP credential and any
// remaining backup codes. Callers MUST verify current possession (a valid
// TOTP code or backup code — see handlers.DisableTOTP) before calling this;
// this function itself does not re-check possession, so it must never be
// reachable from an authenticated-session-only code path.
func DisableTOTPCredential(ctx context.Context, pool *pgxpool.Pool, userID string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM totp_credentials WHERE user_id=$1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM totp_backup_codes WHERE user_id=$1`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CreateTOTPLoginChallenge stands up a short-lived (5-minute) server-side
// challenge after password auth succeeds for a user with TOTP enabled.
// Login does not issue a token at that point — the client must redeem this
// challenge with a code via ResolveTOTPLoginChallenge + VerifyTOTPCode/
// VerifyTOTPBackupCode. Any previous pending challenge for the user is
// invalidated first (same "only the newest is valid" pattern as
// StoreSMSOTP/BeginTOTPSetup), so a stale challenge from an abandoned login
// attempt can't be redeemed later.
func CreateTOTPLoginChallenge(ctx context.Context, pool *pgxpool.Pool, userID string) (challengeID string, err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `DELETE FROM totp_login_challenges WHERE user_id=$1`, userID); err != nil {
		return "", err
	}
	if err := tx.QueryRow(ctx,
		`INSERT INTO totp_login_challenges (user_id) VALUES ($1) RETURNING challenge_id`,
		userID,
	).Scan(&challengeID); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return challengeID, nil
}

// ResolveTOTPLoginChallenge resolves a still-valid (unexpired) login
// challenge to the user id and username needed to verify a code and issue a
// token. It does not consume the challenge — callers must call
// DeleteTOTPLoginChallenge once a code has actually been accepted, so a
// wrong first guess doesn't burn the challenge and force the user to
// restart the whole login.
func ResolveTOTPLoginChallenge(ctx context.Context, pool *pgxpool.Pool, challengeID string) (userID, username string, err error) {
	err = pool.QueryRow(ctx,
		`SELECT c.user_id, u.username
		 FROM totp_login_challenges c JOIN users u ON u.id = c.user_id
		 WHERE c.challenge_id = $1 AND c.expires_at > now()`,
		challengeID,
	).Scan(&userID, &username)
	if err != nil {
		return "", "", ErrChallengeInvalid
	}
	return userID, username, nil
}

// DeleteTOTPLoginChallenge consumes (single-use) a login challenge after a
// successful code verification.
func DeleteTOTPLoginChallenge(ctx context.Context, pool *pgxpool.Pool, challengeID string) {
	// Best-effort cleanup only: the challenge already did its job (a token
	// was issued). Leaving a stale row behind just means it sits until its
	// own expires_at — it can't be redeemed a second time for a *different*
	// code because the token was already issued for this login, and a
	// same-challenge replay would just re-verify the same TOTP code, which
	// is itself time-windowed and rate-limited.
	_, _ = pool.Exec(ctx, `DELETE FROM totp_login_challenges WHERE challenge_id=$1`, challengeID)
}

// validateTOTPCode is the single place that calls into pquerna/otp for
// RFC 6238 validation — every code check in this file (enrollment confirm,
// login step-up, disable re-proof) goes through here so the time-step,
// skew, digit count, and algorithm are always consistent.
func validateTOTPCode(secret, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpSkew,
		Digits:    totpDigits,
		Algorithm: totpAlgo,
	})
	return err == nil && valid
}

// generateBackupCodes returns numBackupCodes freshly generated plaintext
// codes and their bcrypt hashes (same primitive password hashing already
// uses in this codebase — see internal/user/service.go — no new hashing
// primitive introduced). Codes are generated with crypto/rand, never
// math/rand.
func generateBackupCodes(bcryptCost int) (plain []string, hashes []string, err error) {
	plain = make([]string, 0, numBackupCodes)
	hashes = make([]string, 0, numBackupCodes)
	for i := 0; i < numBackupCodes; i++ {
		code, err := generateBackupCode()
		if err != nil {
			return nil, nil, err
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(canonicalizeBackupCode(code)), bcryptCost)
		if err != nil {
			return nil, nil, err
		}
		plain = append(plain, code)
		hashes = append(hashes, string(hash))
	}
	return plain, hashes, nil
}

// generateBackupCode returns one human-typeable recovery code, e.g.
// "ABCDE-FGHIJ", drawn from crypto/rand (never math/rand — these gate
// account access exactly like a password).
func generateBackupCode() (string, error) {
	b := make([]byte, backupCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	if len(enc) < 8 {
		return "", errors.New("mfa: short backup code encoding")
	}
	return enc[:4] + "-" + enc[4:8], nil
}

// canonicalizeBackupCode normalizes a user-submitted backup code (strip
// whitespace/dashes, uppercase) so formatting differences at input time
// never cause a legitimate code to fail the bcrypt comparison.
func canonicalizeBackupCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return code
}
