package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
)

func TestForgotPassword_BadJSON_Returns400(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/forgot-password", bytes.NewReader([]byte(`{bad`)))
	w := httptest.NewRecorder()

	handlers.ForgotPassword(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestForgotPassword_UnknownEmail_ReturnsGenericOK(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}

	body, _ := json.Marshal(map[string]string{"email": "nobody-" + handlers.RandomSuffix() + "@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/forgot-password", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.ForgotPassword(d)(w, req)

	// Must not reveal whether the email exists: same 200 + generic message as the success path.
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for unknown email (anti-enumeration), got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] == "" {
		t.Error("expected a generic message")
	}
}

func TestForgotPassword_Success_CreatesToken(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool} // Mailer left nil: exercises the "log instead of send" branch.
	username := "fp_" + handlers.RandomSuffix()
	email := username + "@example.com"

	var userID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email) VALUES ($1,$2) RETURNING id`, username, email,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	body, _ := json.Marshal(map[string]string{"email": email})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/forgot-password", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.ForgotPassword(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM password_reset_tokens WHERE user_id=$1 AND used=false AND expires_at > now()`,
		userID,
	).Scan(&count); err != nil {
		t.Fatalf("query tokens: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly one active reset token, got %d", count)
	}
}

func TestResetPassword_BadJSON_Returns400(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", bytes.NewReader([]byte(`{bad`)))
	w := httptest.NewRecorder()

	handlers.ResetPassword(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestResetPassword_ShortPassword_Returns400(t *testing.T) {
	d := handlers.Deps{}
	body, _ := json.Marshal(map[string]string{"token": "whatever", "password": "short"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.ResetPassword(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d", w.Code)
	}
}

func TestResetPassword_InvalidToken_Returns400(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}

	body, _ := json.Marshal(map[string]string{
		"token":    "does-not-exist-" + handlers.RandomSuffix(),
		"password": "newpassword123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.ResetPassword(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown token, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestResetPassword_ExpiredToken_Returns400(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "rp_" + handlers.RandomSuffix()

	var userID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username) VALUES ($1) RETURNING id`, username,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	token := "tok_expired_" + handlers.RandomSuffix()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1,$2, now() - interval '1 hour')`,
		userID, token,
	); err != nil {
		t.Fatalf("insert expired token: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"token": token, "password": "newpassword123"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.ResetPassword(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired token, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestResetPassword_Success_ThenTokenSingleUse is the core security test for
// this handler: a reset token must update the password exactly once and be
// permanently rejected on any subsequent replay, even though it is not yet
// expired and was never deleted (only marked used=true).
func TestResetPassword_Success_ThenTokenSingleUse(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "rp_" + handlers.RandomSuffix()

	var userID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, password_hash) VALUES ($1,'old-hash') RETURNING id`, username,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	token := "tok_valid_" + handlers.RandomSuffix()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1,$2, now() + interval '1 hour')`,
		userID, token,
	); err != nil {
		t.Fatalf("insert token: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"token": token, "password": "newpassword123"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handlers.ResetPassword(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on first (legitimate) use, got %d — body: %s", w.Code, w.Body.String())
	}

	var hash string
	var used bool
	if err := pool.QueryRow(context.Background(),
		`SELECT password_hash, used FROM users u JOIN password_reset_tokens t ON t.user_id = u.id WHERE t.token=$1`,
		token,
	).Scan(&hash, &used); err != nil {
		t.Fatalf("query updated row: %v", err)
	}
	if hash == "old-hash" {
		t.Error("expected password_hash to be updated")
	}
	if !used {
		t.Error("expected token to be marked used=true after a successful reset")
	}

	// Replay with the exact same token must be rejected (single-use enforcement).
	body2, _ := json.Marshal(map[string]string{"token": token, "password": "anotherpassword456"})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	handlers.ResetPassword(d)(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when replaying an already-used reset token, got %d — body: %s", w2.Code, w2.Body.String())
	}

	var hashAfterReplay string
	if err := pool.QueryRow(context.Background(),
		`SELECT password_hash FROM users WHERE id=$1`, userID,
	).Scan(&hashAfterReplay); err != nil {
		t.Fatalf("query user: %v", err)
	}
	if hashAfterReplay != hash {
		t.Error("password_hash must not change again when the reset token is replayed")
	}
}

// TestResetPassword_ConcurrentReplay_OnlyOneSucceeds exercises the FOR UPDATE
// row lock: two concurrent requests racing on the same token must not both
// succeed — the transaction serializes them, and the loser sees the
// already-used token.
func TestResetPassword_ConcurrentReplay_OnlyOneSucceeds(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "rp_race_" + handlers.RandomSuffix()

	var userID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username) VALUES ($1) RETURNING id`, username,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	token := "tok_race_" + handlers.RandomSuffix()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1,$2, now() + interval '1 hour')`,
		userID, token,
	); err != nil {
		t.Fatalf("insert token: %v", err)
	}

	results := make(chan int, 2)
	race := func() {
		body, _ := json.Marshal(map[string]string{"token": token, "password": "racepassword123"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/reset-password", bytes.NewReader(body))
		w := httptest.NewRecorder()
		handlers.ResetPassword(d)(w, req)
		results <- w.Code
	}
	go race()
	go race()

	code1 := <-results
	code2 := <-results

	successCount := 0
	for _, c := range []int{code1, code2} {
		if c == http.StatusOK {
			successCount++
		} else if c != http.StatusBadRequest {
			t.Errorf("unexpected status code %d in concurrent reset race", c)
		}
	}
	if successCount != 1 {
		t.Fatalf("expected exactly one of two concurrent resets to succeed, got %d (codes: %d, %d)", successCount, code1, code2)
	}
}
