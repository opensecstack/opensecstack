package handlers

// DB-backed tests for Login's database-registered-user path (auth.go).
// The config-hardcoded-user path is already covered externally in
// auth_test.go; this file exercises everything that only triggers once a
// real `users` row exists: bcrypt verification, legacy-sha256-to-bcrypt
// migration, per-account lockout, deactivated accounts, and TOTP
// enforcement. These are the actual authentication decisions an attacker
// would try to bypass, so they're tested against a real Postgres instance
// rather than mocked.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/opensecstack/community/internal/config"
)

func loginTestDeps(t *testing.T) (Deps, func(username string)) {
	t.Helper()
	pool := NewTestDBPool(t)
	d := Deps{
		Pool: pool,
		Cfg: &config.Config{
			JWTSecret: "unit-test-secret-unit-test-secret",
			JWTIssuer: "test",
			TokenTTL:  3_600_000_000_000,
			Pepper:    "test-pepper",
		},
	}
	cleanup := func(username string) {
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE username=$1`, username)
		})
	}
	return d, cleanup
}

func doLogin(t *testing.T, d Deps, username, password, totpCode string) *httptest.ResponseRecorder {
	t.Helper()
	payload := map[string]string{"username": username, "password": password}
	if totpCode != "" {
		payload["totp_code"] = totpCode
	}
	b, _ := json.Marshal(payload)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.5:12345"
	w := httptest.NewRecorder()
	Login(d)(w, req)
	return w
}

// ---------------------------------------------------------------------------
// bcrypt password verification
// ---------------------------------------------------------------------------

func TestLogin_DBUser_BcryptPassword_CorrectCredentials_Returns200(t *testing.T) {
	d, cleanup := loginTestDeps(t)
	username := "bcuser_" + RandomSuffix()
	cleanup(username)

	hash, err := bcryptHash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	_, err = d.Pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified) VALUES ($1,$1,'author',$2,true)`,
		username, hash)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := doLogin(t, d, username, "correct horse battery staple", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("expected non-empty token")
	}
}

func TestLogin_DBUser_BcryptPassword_WrongPassword_Returns401(t *testing.T) {
	d, cleanup := loginTestDeps(t)
	username := "bcuser2_" + RandomSuffix()
	cleanup(username)

	hash, _ := bcryptHash("the-real-password")
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified) VALUES ($1,$1,'author',$2,true)`,
		username, hash)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := doLogin(t, d, username, "a-wrong-guess", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Legacy sha256 -> bcrypt migration
// ---------------------------------------------------------------------------

func TestLogin_LegacySHA256Hash_CorrectPassword_MigratesToBcrypt(t *testing.T) {
	d, cleanup := loginTestDeps(t)
	username := "legacyuser_" + RandomSuffix()
	cleanup(username)

	legacyHash := sha256Hash(d.Cfg.Pepper + ":" + "legacy-password")
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified) VALUES ($1,$1,'author',$2,true)`,
		username, legacyHash)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := doLogin(t, d, username, "legacy-password", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on correct legacy password, got %d — body: %s", w.Code, w.Body.String())
	}

	var storedHash string
	if err := d.Pool.QueryRow(context.Background(), `SELECT password_hash FROM users WHERE username=$1`, username).Scan(&storedHash); err != nil {
		t.Fatalf("query: %v", err)
	}
	if storedHash == legacyHash {
		t.Error("expected password_hash to be migrated to bcrypt after successful legacy login")
	}
	if !bcryptVerify("legacy-password", storedHash) {
		t.Error("expected the migrated bcrypt hash to still verify the original password")
	}

	// Second login must now succeed via the bcrypt path too.
	w2 := doLogin(t, d, username, "legacy-password", "")
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 on second (post-migration) login, got %d", w2.Code)
	}
}

func TestLogin_LegacySHA256Hash_WrongPassword_Returns401_NoMigration(t *testing.T) {
	d, cleanup := loginTestDeps(t)
	username := "legacyuser2_" + RandomSuffix()
	cleanup(username)

	legacyHash := sha256Hash(d.Cfg.Pepper + ":" + "legacy-password")
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified) VALUES ($1,$1,'author',$2,true)`,
		username, legacyHash)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := doLogin(t, d, username, "wrong-password", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var storedHash string
	if err := d.Pool.QueryRow(context.Background(), `SELECT password_hash FROM users WHERE username=$1`, username).Scan(&storedHash); err != nil {
		t.Fatalf("query: %v", err)
	}
	if storedHash != legacyHash {
		t.Error("a failed login must not migrate/rewrite the stored hash")
	}
}

// ---------------------------------------------------------------------------
// Enumeration resistance: unknown user vs known user + wrong password must
// look identical to the client (both 401 "invalid credentials").
// ---------------------------------------------------------------------------

func TestLogin_UnknownVsWrongPassword_SameErrorShape(t *testing.T) {
	d, cleanup := loginTestDeps(t)
	username := "enumuser_" + RandomSuffix()
	cleanup(username)

	hash, _ := bcryptHash("real-password")
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified) VALUES ($1,$1,'author',$2,true)`,
		username, hash)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	wUnknown := doLogin(t, d, "definitely-does-not-exist-"+RandomSuffix(), "whatever", "")
	wWrongPW := doLogin(t, d, username, "wrong-password", "")

	if wUnknown.Code != wWrongPW.Code {
		t.Errorf("expected identical status codes for unknown-user vs wrong-password, got %d vs %d", wUnknown.Code, wWrongPW.Code)
	}
	var eu, ew map[string]string
	_ = json.NewDecoder(wUnknown.Body).Decode(&eu)
	_ = json.NewDecoder(wWrongPW.Body).Decode(&ew)
	if eu["error"] != ew["error"] {
		t.Errorf("expected identical error messages (no user-enumeration leak), got %q vs %q", eu["error"], ew["error"])
	}
}

// ---------------------------------------------------------------------------
// Deactivated accounts
// ---------------------------------------------------------------------------

func TestLogin_DeactivatedAccount_Returns403(t *testing.T) {
	d, cleanup := loginTestDeps(t)
	username := "deactuser_" + RandomSuffix()
	cleanup(username)

	hash, _ := bcryptHash("password123")
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified, deactivated_at) VALUES ($1,$1,'author',$2,true,now())`,
		username, hash)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := doLogin(t, d, username, "password123", "")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for deactivated account, got %d — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TOTP / 2FA enforcement
// ---------------------------------------------------------------------------

func TestLogin_TOTPEnabled_NoCode_ReturnsRequireTOTP_NoToken(t *testing.T) {
	d, cleanup := loginTestDeps(t)
	username := "totpuser_" + RandomSuffix()
	cleanup(username)

	hash, _ := bcryptHash("password123")
	secret := "JBSWY3DPEHPK3PXP"
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified, totp_secret, totp_enabled) VALUES ($1,$1,'author',$2,true,$3,true)`,
		username, hash, secret)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := doLogin(t, d, username, "password123", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (require_totp signal), got %d", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if requireTOTP, _ := resp["require_totp"].(bool); !requireTOTP {
		t.Error("expected require_totp=true")
	}
	if _, hasToken := resp["token"]; hasToken {
		t.Error("SECURITY: must NOT issue a JWT before the TOTP code is verified")
	}
}

func TestLogin_TOTPEnabled_WrongCode_Returns401_NoToken(t *testing.T) {
	d, cleanup := loginTestDeps(t)
	username := "totpuser2_" + RandomSuffix()
	cleanup(username)

	hash, _ := bcryptHash("password123")
	secret := "JBSWY3DPEHPK3PXP"
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified, totp_secret, totp_enabled) VALUES ($1,$1,'author',$2,true,$3,true)`,
		username, hash, secret)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := doLogin(t, d, username, "password123", "000000")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong TOTP code, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestLogin_TOTPEnabled_CorrectCode_Returns200WithToken(t *testing.T) {
	d, cleanup := loginTestDeps(t)
	username := "totpuser3_" + RandomSuffix()
	cleanup(username)

	hash, _ := bcryptHash("password123")
	secret := "JBSWY3DPEHPK3PXP"
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified, totp_secret, totp_enabled) VALUES ($1,$1,'author',$2,true,$3,true)`,
		username, hash, secret)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}

	w := doLogin(t, d, username, "password123", code)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid TOTP code, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Token == "" {
		t.Error("expected a token once TOTP is verified")
	}
}

// ---------------------------------------------------------------------------
// Per-account lockout (brute-force protection) — end to end through Login
// ---------------------------------------------------------------------------

func TestLogin_LockoutAfterRepeatedFailures_Returns429EvenWithCorrectPassword(t *testing.T) {
	d, cleanup := loginTestDeps(t)
	username := "lockuser_" + RandomSuffix()
	cleanup(username)
	t.Cleanup(func() { clearFailures(username) })

	hash, _ := bcryptHash("password123")
	_, err := d.Pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified) VALUES ($1,$1,'author',$2,true)`,
		username, hash)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	for i := 0; i < lockoutMaxFails; i++ {
		w := doLogin(t, d, username, "wrong-password", "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, w.Code)
		}
	}

	// Even the CORRECT password must now be rejected — lockout is checked
	// before the password comparison.
	w := doLogin(t, d, username, "password123", "")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once locked out (even with correct password), got %d — body: %s", w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// recordSession
// ---------------------------------------------------------------------------

func TestLogin_Success_RecordsSession(t *testing.T) {
	// recordSession backs the "active sessions" / "log out other devices"
	// feature; a successful login must leave a matching user_sessions row
	// (hashed token, never the raw token) so that feature has data to show.
	d, cleanup := loginTestDeps(t)
	username := "sessuser_" + RandomSuffix()
	cleanup(username)

	hash, _ := bcryptHash("password123")
	var userID string
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO users (username, display_name, role, password_hash, email_verified) VALUES ($1,$1,'author',$2,true) RETURNING id`,
		username, hash).Scan(&userID)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := doLogin(t, d, username, "password123", "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)

	var count int
	if err := d.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_sessions WHERE user_id=$1 AND token_hash=$2`,
		userID, tokenHash(resp.Token),
	).Scan(&count); err != nil {
		t.Fatalf("query session: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly one user_sessions row for the issued token, got %d", count)
	}

	// Confirm the raw token itself was never stored.
	var rawStored int
	if err := d.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_sessions WHERE token_hash=$1`, resp.Token,
	).Scan(&rawStored); err != nil {
		t.Fatalf("query: %v", err)
	}
	if rawStored != 0 {
		t.Error("SECURITY: raw JWT must never be stored as token_hash — only its hash")
	}
}

func TestRecordSession_DBUnreachable_DoesNotPanic(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)
	// Must not panic even though the INSERT will fail — recordSession is
	// best-effort and Login should not 500 just because session logging
	// failed.
	recordSession(req, d, "not-a-real-uuid", "tok", time.Now().Add(time.Hour))
}

// ---------------------------------------------------------------------------
// issueOAuthJWT
// ---------------------------------------------------------------------------

func TestIssueOAuthJWT_ReturnsSignedToken(t *testing.T) {
	d := Deps{Cfg: &config.Config{JWTSecret: "s", JWTIssuer: "test-issuer", TokenTTL: time.Hour}}
	tok, err := issueOAuthJWT(d, "someuser", "author")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
}

// ---------------------------------------------------------------------------
// requireRole
// ---------------------------------------------------------------------------

func TestRequireRole_NoClaims_Returns403(t *testing.T) {
	d := Deps{}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	if requireRole(d, req, w, "admin") {
		t.Error("expected requireRole to return false with no claims in context")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}
