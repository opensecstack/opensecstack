package handlers_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

// bcryptHashForTest and sha256HashForTest mirror the two password-hashing
// schemes used in production (bcryptHash / sha256Hash in auth.go), which are
// unexported and unreachable from this external test package. Duplicating
// the (trivial) hashing call here lets these tests seed both kinds of
// account exactly as Register / legacy accounts would look in the real DB.
func bcryptHashForTest(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(b), err
}

func sha256HashForTest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// withClaims injects auth.Claims into the request context the same way the
// Auth middleware does, so handlers can call middleware.ClaimsFrom(ctx).
func withClaims(r *http.Request, claims *auth.Claims) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.ClaimsKey, claims)
	return r.WithContext(ctx)
}

func TestChangePassword_NoToken_Returns401(t *testing.T) {
	d := handlers.Deps{
		Cfg: &config.Config{},
	}

	body, _ := json.Marshal(map[string]string{
		"current_password": "oldpass",
		"new_password":     "newpass123",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No claims injected — simulates missing/invalid JWT.
	w := httptest.NewRecorder()

	handlers.ChangePassword(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

func TestChangePassword_ShortNewPassword_Returns422(t *testing.T) {
	d := newDepsWithBadDB(t)

	claims := &auth.Claims{Sub: "testuser", Role: "author"}
	body, _ := json.Marshal(map[string]string{
		"current_password": "oldpass",
		"new_password":     "short",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, claims)

	w := httptest.NewRecorder()
	handlers.ChangePassword(d)(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for short password, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["error"] == "" {
		t.Error("expected non-empty error message")
	}
}

func TestChangePassword_BadJSON_Returns400(t *testing.T) {
	d := handlers.Deps{
		Cfg: &config.Config{},
	}

	claims := &auth.Claims{Sub: "testuser", Role: "author"}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/password", bytes.NewReader([]byte(`{bad json}`)))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, claims)

	w := httptest.NewRecorder()
	handlers.ChangePassword(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", w.Code)
	}
}

// --- Live-DB tests: bcrypt-hashed accounts (the normal case) ---
//
// Regression coverage for a real bug: ChangePassword used to verify the
// current password using ONLY the legacy sha256(pepper+password) scheme,
// while Register (the only path that creates new accounts) stores bcrypt
// hashes exclusively. That meant every normal user got "current password is
// incorrect" for a correct password, and a change could never succeed. These
// tests exercise the fixed bcrypt-aware verification end to end.

func TestChangePassword_BcryptAccount_CorrectPassword_Succeeds_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)
	ctx := context.Background()

	uid, username := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)

	// Simulate what Register actually does: store a bcrypt hash.
	bcryptHash, err := bcryptHashForTest("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, bcryptHash, uid); err != nil {
		t.Fatalf("seed password hash: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"current_password": "correct-horse-battery-staple",
		"new_password":     "brand-new-password-123",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()
	handlers.ChangePassword(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 changing password for a bcrypt-hashed account with the correct current password, got %d — body: %s", w.Code, w.Body.String())
	}

	// The new hash must itself be bcrypt (never downgraded to sha256+pepper).
	var newHash string
	_ = pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, uid).Scan(&newHash)
	if !strings.HasPrefix(newHash, "$2") {
		t.Errorf("expected new password to be stored as a bcrypt hash, got a hash that does not look like bcrypt: %q", newHash)
	}
}

func TestChangePassword_BcryptAccount_WrongPassword_Returns400_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)
	ctx := context.Background()

	uid, username := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)

	bcryptHash, err := bcryptHashForTest("the-real-password")
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, bcryptHash, uid); err != nil {
		t.Fatalf("seed password hash: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"current_password": "totally-wrong",
		"new_password":     "brand-new-password-123",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()
	handlers.ChangePassword(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong current password, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestChangePassword_LegacySha256Account_CorrectPassword_MigratesToBcrypt_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)
	ctx := context.Background()

	pepper := "test-pepper"
	uid, username := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)

	legacyHash := sha256HashForTest(pepper + ":old-legacy-password")
	if _, err := pool.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, legacyHash, uid); err != nil {
		t.Fatalf("seed legacy password hash: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"current_password": "old-legacy-password",
		"new_password":     "brand-new-password-123",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()
	handlers.ChangePassword(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for a legacy sha256 account with correct current password, got %d — body: %s", w.Code, w.Body.String())
	}

	var newHash string
	_ = pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=$1`, uid).Scan(&newHash)
	if !strings.HasPrefix(newHash, "$2") {
		t.Errorf("expected the new password to migrate to bcrypt, got %q", newHash)
	}
}
