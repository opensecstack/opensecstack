package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func TestSetupTOTP_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/totp/setup", nil)
	w := httptest.NewRecorder()

	handlers.SetupTOTP(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestSetupTOTP_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/totp/setup", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.SetupTOTP(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestConfirmTOTP_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/totp/confirm", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()

	handlers.ConfirmTOTP(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestConfirmTOTP_MissingFields_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/totp/confirm", bytes.NewReader([]byte(`{"setup_id":"","code":""}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ConfirmTOTP(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing setup_id/code, got %d", w.Code)
	}
}

func TestConfirmTOTP_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/totp/confirm", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ConfirmTOTP(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestConfirmTOTP_InvalidSetupSession_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/totp/confirm", bytes.NewReader([]byte(`{"setup_id":"abc","code":"123456"}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.ConfirmTOTP(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when the setup session cannot be resolved, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestDisableTOTP_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/totp", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()

	handlers.DisableTOTP(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestDisableTOTP_BadJSON_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/totp", bytes.NewReader([]byte(`{bad`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.DisableTOTP(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestDisableTOTP_2FANotEnabled_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/totp", bytes.NewReader([]byte(`{"code":"123456"}`)))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.DisableTOTP(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when secret cannot be resolved (2FA not enabled path), got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestGetTOTPStatus_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/totp", nil)
	w := httptest.NewRecorder()

	handlers.GetTOTPStatus(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestGetTOTPStatus_DBError_Returns500(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/totp", nil)
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetTOTPStatus(d)(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", w.Code)
	}
}

// ---------- live-DB success-path + security tests ----------

func TestGetTOTPStatus_Success_Disabled(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool, Cfg: &config.Config{}}
	username := "totp_" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/totp", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.GetTOTPStatus(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]bool
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["enabled"] {
		t.Error("expected enabled=false for a freshly created user")
	}
}

func TestSetupTOTP_Success(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool, Cfg: &config.Config{}}
	username := "totp_" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/totp/setup", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.SetupTOTP(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["setup_id"] == "" {
		t.Error("expected non-empty setup_id")
	}
	if resp["qr_code"] == "" {
		t.Error("expected non-empty qr_code")
	}

	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM totp_setup_sessions WHERE setup_id = $1 AND username = $2`,
		resp["setup_id"], username,
	).Scan(&count); err != nil {
		t.Fatalf("query setup session: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly one stored setup session, got %d", count)
	}
}

func TestConfirmTOTP_Success_ThenSetupSessionSingleUse(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool, Cfg: &config.Config{}}
	username := "totp_" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "SIN", AccountName: username})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := key.Secret()

	var setupID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO totp_setup_sessions (username, secret) VALUES ($1,$2) RETURNING setup_id`,
		username, secret,
	).Scan(&setupID); err != nil {
		t.Fatalf("insert setup session: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"setup_id": setupID, "code": code})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/totp/confirm", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ConfirmTOTP(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}

	var enabled bool
	if err := pool.QueryRow(context.Background(),
		`SELECT totp_enabled FROM users WHERE username=$1`, username,
	).Scan(&enabled); err != nil {
		t.Fatalf("query user: %v", err)
	}
	if !enabled {
		t.Error("expected totp_enabled=true after successful confirm")
	}

	// Replaying the same setup_id must fail: ConfirmTOTP atomically deletes the
	// setup session on first use, so a captured setup_id + code pair cannot be
	// replayed to re-run confirmation.
	body2, _ := json.Marshal(map[string]string{"setup_id": setupID, "code": code})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/me/totp/confirm", bytes.NewReader(body2))
	req2 = withClaims(req2, &auth.Claims{Sub: username, Role: "author"})
	w2 := httptest.NewRecorder()

	handlers.ConfirmTOTP(d)(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when replaying an already-consumed setup session, got %d", w2.Code)
	}
}

func TestConfirmTOTP_InvalidCode_Returns400(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool, Cfg: &config.Config{}}
	username := "totp_" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "SIN", AccountName: username})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	var setupID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO totp_setup_sessions (username, secret) VALUES ($1,$2) RETURNING setup_id`,
		username, key.Secret(),
	).Scan(&setupID); err != nil {
		t.Fatalf("insert setup session: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"setup_id": setupID, "code": "000000"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/totp/confirm", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ConfirmTOTP(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong code, got %d — body: %s", w.Code, w.Body.String())
	}
}

// TestDisableTOTP_CodeReplay_Rejected proves the fix for the replay gap
// previously documented here: DisableTOTP now rejects a captured OTP code on
// its second use. ConsumeTOTPCode persists the time-step of every successful
// validation in users.totp_last_step and only accepts a strictly later step,
// so the same code can never be consumed twice — even though pquerna/otp's
// totp.Validate alone would still accept it across its ~90s Skew:1 window.
func TestDisableTOTP_CodeReplay_Rejected(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool, Cfg: &config.Config{}}
	username := "totp_" + handlers.RandomSuffix()

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	handlers.CleanupUserByUsername(t, pool, username)

	key, err := totp.Generate(totp.GenerateOpts{Issuer: "SIN", AccountName: username})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	secret := key.Secret()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	enableSecret := func() {
		if _, err := pool.Exec(context.Background(),
			`UPDATE users SET totp_secret=$1, totp_enabled=true WHERE username=$2`,
			secret, username,
		); err != nil {
			t.Fatalf("enable totp: %v", err)
		}
	}

	// First use: disable 2FA with a freshly computed, valid code. This must
	// succeed — establishes the code is genuinely valid.
	enableSecret()
	body1, _ := json.Marshal(map[string]string{"code": code})
	req1 := httptest.NewRequest(http.MethodDelete, "/api/v1/me/totp", bytes.NewReader(body1))
	req1 = withClaims(req1, &auth.Claims{Sub: username, Role: "author"})
	w1 := httptest.NewRecorder()
	handlers.DisableTOTP(d)(w1, req1)
	if w1.Code != http.StatusNoContent {
		t.Fatalf("expected first DisableTOTP call to succeed with 204, got %d — body: %s", w1.Code, w1.Body.String())
	}

	// Re-arm the same secret (e.g. the user re-enrolled, or an admin path
	// re-enabled it) and replay the *exact same* code captured earlier.
	enableSecret()
	body2, _ := json.Marshal(map[string]string{"code": code})
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/me/totp", bytes.NewReader(body2))
	req2 = withClaims(req2, &auth.Claims{Sub: username, Role: "author"})
	w2 := httptest.NewRecorder()
	handlers.DisableTOTP(d)(w2, req2)

	if w2.Code == http.StatusNoContent {
		t.Fatal("replayed OTP code was accepted a second time — totp_last_step anti-replay is not working")
	}
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected replay to be rejected with 401, got %d — body: %s", w2.Code, w2.Body.String())
	}
}
