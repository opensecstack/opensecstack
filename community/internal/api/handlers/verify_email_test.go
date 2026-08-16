package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestVerifyEmail_MissingToken_Returns400(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email", nil)
	w := httptest.NewRecorder()

	handlers.VerifyEmail(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing token, got %d", w.Code)
	}
}

func TestVerifyEmail_InvalidToken_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email?token=bogus", nil)
	w := httptest.NewRecorder()

	handlers.VerifyEmail(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unresolvable token, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestResendVerification_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification", nil)
	w := httptest.NewRecorder()

	handlers.ResendVerification(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestResendVerification_UserNotFound_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ResendVerification(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when user lookup fails, got %d — body: %s", w.Code, w.Body.String())
	}
}

// --- Live-DB tests: full verify-email lifecycle ---

func TestVerifyEmail_ValidToken_MarksVerifiedAndConsumesToken_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)
	ctx := context.Background()

	uid, _ := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)

	token := "tok-" + uid
	if _, err := pool.Exec(ctx,
		`INSERT INTO email_verify_tokens (id, user_id, token, expires_at, used, created_at)
		 VALUES (gen_random_uuid(), $1, $2, now() + interval '1 hour', false, now())`,
		uid, token); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email?token="+token, nil)
	w := httptest.NewRecorder()
	handlers.VerifyEmail(d)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	var verified bool
	_ = pool.QueryRow(ctx, `SELECT email_verified FROM users WHERE id=$1`, uid).Scan(&verified)
	if !verified {
		t.Errorf("expected user.email_verified=true after verification")
	}

	var used bool
	_ = pool.QueryRow(ctx, `SELECT used FROM email_verify_tokens WHERE token=$1`, token).Scan(&used)
	if !used {
		t.Errorf("expected token marked used after verification")
	}

	// Re-using the same (now-used) token must fail.
	reuseW := httptest.NewRecorder()
	handlers.VerifyEmail(d)(reuseW, req)
	if reuseW.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when reusing an already-used token, got %d", reuseW.Code)
	}
}

func TestVerifyEmail_ExpiredToken_Returns400_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)
	ctx := context.Background()

	uid, _ := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)

	token := "expired-tok-" + uid
	if _, err := pool.Exec(ctx,
		`INSERT INTO email_verify_tokens (id, user_id, token, expires_at, used, created_at)
		 VALUES (gen_random_uuid(), $1, $2, now() - interval '1 hour', false, now())`,
		uid, token); err != nil {
		t.Fatalf("seed expired token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/verify-email?token="+token, nil)
	w := httptest.NewRecorder()
	handlers.VerifyEmail(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired token, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestResendVerification_AlreadyVerified_Returns400_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)
	ctx := context.Background()

	uid, username := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)
	if _, err := pool.Exec(ctx, `UPDATE users SET email_verified=true WHERE id=$1`, uid); err != nil {
		t.Fatalf("mark verified: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()
	handlers.ResendVerification(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for already-verified user, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestResendVerification_NotYetVerified_CreatesToken_LiveDB(t *testing.T) {
	pool := live13Pool(t)
	d := newLiveDeps13(t)
	ctx := context.Background()

	uid, username := mkUser13(t, pool, "author")
	defer cleanup13(pool, "users", "id", uid)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()
	handlers.ResendVerification(d)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["message"] == "" {
		t.Errorf("expected non-empty confirmation message")
	}

	var count int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_verify_tokens WHERE user_id=$1 AND used=false`, uid).Scan(&count)
	if count != 1 {
		t.Errorf("expected exactly 1 unused token created, got %d", count)
	}
}
