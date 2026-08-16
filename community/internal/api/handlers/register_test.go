package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/config"
)

func registerTestCfg() *config.Config {
	return &config.Config{
		JWTSecret: "test-secret-at-least-32-bytes-long!!",
		JWTIssuer: "community-test",
		TokenTTL:  time.Hour,
	}
}

func TestRegister_BadJSON_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: registerTestCfg()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader([]byte(`{bad`)))
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestRegister_InvalidUsername_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: registerTestCfg()}
	body, _ := json.Marshal(map[string]string{
		"username": "a", // too short
		"email":    "a@example.com",
		"password": "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid username, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestRegister_InvalidEmail_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: registerTestCfg()}
	body, _ := json.Marshal(map[string]string{
		"username": "valid_user_1",
		"email":    "not-an-email",
		"password": "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid email, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestRegister_EmailWithoutDottedDomain_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: registerTestCfg()}
	body, _ := json.Marshal(map[string]string{
		"username": "valid_user_2",
		"email":    "user@localhost",
		"password": "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for email host missing a dot, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestRegister_ShortPassword_Returns400(t *testing.T) {
	d := handlers.Deps{Cfg: registerTestCfg()}
	body, _ := json.Marshal(map[string]string{
		"username": "valid_user_3",
		"email":    "user3@example.com",
		"password": "short",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestRegister_InviteOnly_MissingCode_Returns400(t *testing.T) {
	cfg := registerTestCfg()
	cfg.InviteOnly = true
	d := handlers.Deps{Cfg: cfg}
	body, _ := json.Marshal(map[string]string{
		"username": "valid_user_4",
		"email":    "user4@example.com",
		"password": "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when invite-only and no code supplied, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestRegister_InviteCode_NotFound_Returns400(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool, Cfg: registerTestCfg()}
	body, _ := json.Marshal(map[string]string{
		"username":    "valid_user_5",
		"email":       "user5@example.com",
		"password":    "password123",
		"invite_code": "does-not-exist-" + handlers.RandomSuffix(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown invite code, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestRegister_EmailDomainNotAllowed_Returns403(t *testing.T) {
	cfg := registerTestCfg()
	cfg.AllowedEmailDomains = []string{"allowed.example"}
	d := handlers.Deps{Cfg: cfg}
	body, _ := json.Marshal(map[string]string{
		"username": "valid_user_6",
		"email":    "user6@notallowed.example",
		"password": "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed email domain, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestRegister_Success(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool, Cfg: registerTestCfg()}
	username := "reg_" + handlers.RandomSuffix()
	email := username + "@example.com"
	handlers.CleanupUserByUsername(t, pool, username)

	body, _ := json.Marshal(map[string]string{
		"username": username,
		"email":    email,
		"password": "password123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handlers.Register(d)(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token         string `json:"token"`
		Role          string `json:"role"`
		Sub           string `json:"sub"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Error("expected a non-empty JWT token")
	}
	if resp.Role != "author" {
		t.Errorf("expected role=author, got %q", resp.Role)
	}
	if resp.Sub != username {
		t.Errorf("expected sub=%q, got %q", username, resp.Sub)
	}
	if resp.EmailVerified {
		t.Error("expected email_verified=false for a brand new account")
	}

	var userID string
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE username=$1 AND email=$2`, username, email,
	).Scan(&userID); err != nil {
		t.Fatalf("expected user row to be created: %v", err)
	}

	var verifyCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM email_verify_tokens WHERE user_id=$1`, userID,
	).Scan(&verifyCount); err != nil {
		t.Fatalf("query verify tokens: %v", err)
	}
	if verifyCount != 1 {
		t.Errorf("expected exactly one email verification token, got %d", verifyCount)
	}

	var sessionCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_sessions WHERE user_id=$1`, userID,
	).Scan(&sessionCount); err != nil {
		t.Fatalf("query sessions: %v", err)
	}
	if sessionCount != 1 {
		t.Errorf("expected the new session to be recorded, got %d", sessionCount)
	}
}

func TestRegister_DuplicateUsername_Returns409(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool, Cfg: registerTestCfg()}
	username := "reg_" + handlers.RandomSuffix()
	handlers.CleanupUserByUsername(t, pool, username)

	body, _ := json.Marshal(map[string]string{
		"username": username,
		"email":    username + "@example.com",
		"password": "password123",
	})

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	w1 := httptest.NewRecorder()
	handlers.Register(d)(w1, req1)
	if w1.Code != http.StatusCreated {
		t.Fatalf("expected first registration to succeed with 201, got %d — body: %s", w1.Code, w1.Body.String())
	}

	body2, _ := json.Marshal(map[string]string{
		"username": username,
		"email":    username + "-2@example.com",
		"password": "password123",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	handlers.Register(d)(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate username, got %d — body: %s", w2.Code, w2.Body.String())
	}
}

func TestRegister_InviteCode_ExpiredAndUsed_Then_Success(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool, Cfg: registerTestCfg()}

	// Creator user the invites reference.
	creator := "reg_creator_" + handlers.RandomSuffix()
	var creatorID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username) VALUES ($1) RETURNING id`, creator,
	).Scan(&creatorID); err != nil {
		t.Fatalf("insert creator: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, creator)

	// Expired invite.
	expiredCode := "exp_" + handlers.RandomSuffix()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO invites (code, created_by, expires_at) VALUES ($1,$2, now() - interval '1 hour')`,
		expiredCode, creatorID,
	); err != nil {
		t.Fatalf("insert expired invite: %v", err)
	}
	expiredUsername := "reg_" + handlers.RandomSuffix()
	handlers.CleanupUserByUsername(t, pool, expiredUsername)
	body, _ := json.Marshal(map[string]string{
		"username":    expiredUsername,
		"email":       expiredUsername + "@example.com",
		"password":    "password123",
		"invite_code": expiredCode,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handlers.Register(d)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired invite, got %d — body: %s", w.Code, w.Body.String())
	}

	// Already-used invite.
	usedCode := "used_" + handlers.RandomSuffix()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO invites (code, created_by, used_by, used_at, expires_at)
		 VALUES ($1,$2,$2, now(), now() + interval '1 hour')`,
		usedCode, creatorID,
	); err != nil {
		t.Fatalf("insert used invite: %v", err)
	}
	usedUsername := "reg_" + handlers.RandomSuffix()
	handlers.CleanupUserByUsername(t, pool, usedUsername)
	body2, _ := json.Marshal(map[string]string{
		"username":    usedUsername,
		"email":       usedUsername + "@example.com",
		"password":    "password123",
		"invite_code": usedCode,
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	handlers.Register(d)(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 for already-used invite, got %d — body: %s", w2.Code, w2.Body.String())
	}

	// Valid invite: registration succeeds and the invite is marked used.
	validCode := "valid_" + handlers.RandomSuffix()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO invites (code, created_by, expires_at) VALUES ($1,$2, now() + interval '1 hour')`,
		validCode, creatorID,
	); err != nil {
		t.Fatalf("insert valid invite: %v", err)
	}
	validUsername := "reg_" + handlers.RandomSuffix()
	handlers.CleanupUserByUsername(t, pool, validUsername)
	body3, _ := json.Marshal(map[string]string{
		"username":    validUsername,
		"email":       validUsername + "@example.com",
		"password":    "password123",
		"invite_code": validCode,
	})
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body3))
	w3 := httptest.NewRecorder()
	handlers.Register(d)(w3, req3)
	if w3.Code != http.StatusCreated {
		t.Fatalf("expected 201 with a valid unused invite, got %d — body: %s", w3.Code, w3.Body.String())
	}

	var usedAt *time.Time
	var usedBy *string
	if err := pool.QueryRow(context.Background(),
		`SELECT used_at, used_by FROM invites WHERE code=$1`, validCode,
	).Scan(&usedAt, &usedBy); err != nil {
		t.Fatalf("query invite: %v", err)
	}
	if usedAt == nil || usedBy == nil {
		t.Error("expected invite to be marked used after successful registration")
	}
}
