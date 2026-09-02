//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/opensecstack/sinauth/internal/mfa"
)

// totpGenCode returns a currently-valid 6-digit code for secret, using the
// same TOTP parameters BeginTOTPEnroll/mfa.VerifyTOTPCode use.
func totpGenCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("totp.GenerateCode: %v", err)
	}
	return code
}

// ── BeginTOTPEnroll ──────────────────────────────────────────────────────

func TestBeginTOTPEnroll_Unauthenticated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/enroll/begin", nil)
	rec := httptest.NewRecorder()
	BeginTOTPEnroll(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBeginTOTPEnroll_Success_ReturnsSecretAndURI_NeverAgain(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-begin-%d", time.Now().UnixNano())
	createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/enroll/begin", nil)
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	BeginTOTPEnroll(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["setup_id"] == "" || resp["secret"] == "" || resp["otpauth_url"] == "" {
		t.Fatalf("response missing expected fields: %+v", resp)
	}
	if !strings.HasPrefix(resp["otpauth_url"], "otpauth://totp/") {
		t.Fatalf("otpauth_url = %q, want otpauth://totp/ prefix", resp["otpauth_url"])
	}
}

// ── ConfirmTOTPEnroll ────────────────────────────────────────────────────

func TestConfirmTOTPEnroll_Unauthenticated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/enroll/confirm", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	ConfirmTOTPEnroll(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestConfirmTOTPEnroll_MissingFields(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-confirm-missing-%d", time.Now().UnixNano())
	createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/enroll/confirm", strings.NewReader(`{}`))
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	ConfirmTOTPEnroll(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestConfirmTOTPEnroll_WrongCode_NotEnabled(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-confirm-wrong-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)

	setupID, _, _, err := mfa.BeginTOTPSetup(context.Background(), pool, userID, username)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}

	body := fmt.Sprintf(`{"setup_id":%q,"code":"000000"}`, setupID)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/enroll/confirm", strings.NewReader(body))
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	ConfirmTOTPEnroll(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	enabled, _ := mfa.IsTOTPEnabled(context.Background(), pool, userID)
	if enabled {
		t.Fatal("totp must not be enabled after a wrong-code confirm attempt")
	}
}

// TestConfirmTOTPEnroll_Success_EnablesAndReturnsBackupCodesOnce is the core
// enrollment happy-path: begin -> confirm with a real code -> totp becomes
// active and a one-time set of backup codes is returned.
func TestConfirmTOTPEnroll_Success_EnablesAndReturnsBackupCodesOnce(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-confirm-ok-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)

	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/enroll/begin", nil)
	beginReq = withClaimsSub(beginReq, username)
	beginRec := httptest.NewRecorder()
	BeginTOTPEnroll(d)(beginRec, beginReq)
	if beginRec.Code != http.StatusOK {
		t.Fatalf("begin: status = %d, body=%s", beginRec.Code, beginRec.Body.String())
	}
	var beginResp map[string]string
	if err := json.Unmarshal(beginRec.Body.Bytes(), &beginResp); err != nil {
		t.Fatalf("unmarshal begin resp: %v", err)
	}

	code := totpGenCode(t, beginResp["secret"])
	confirmBody := fmt.Sprintf(`{"setup_id":%q,"code":%q}`, beginResp["setup_id"], code)
	confirmReq := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/enroll/confirm", strings.NewReader(confirmBody))
	confirmReq = withClaimsSub(confirmReq, username)
	confirmRec := httptest.NewRecorder()
	ConfirmTOTPEnroll(d)(confirmRec, confirmReq)

	if confirmRec.Code != http.StatusOK {
		t.Fatalf("confirm: status = %d, want %d; body=%s", confirmRec.Code, http.StatusOK, confirmRec.Body.String())
	}
	var confirmResp struct {
		Status      string   `json:"status"`
		BackupCodes []string `json:"backup_codes"`
	}
	if err := json.Unmarshal(confirmRec.Body.Bytes(), &confirmResp); err != nil {
		t.Fatalf("unmarshal confirm resp: %v", err)
	}
	if confirmResp.Status != "enabled" {
		t.Fatalf("status = %q, want %q", confirmResp.Status, "enabled")
	}
	if len(confirmResp.BackupCodes) != 10 {
		t.Fatalf("got %d backup codes, want 10", len(confirmResp.BackupCodes))
	}

	enabled, err := mfa.IsTOTPEnabled(context.Background(), pool, userID)
	if err != nil || !enabled {
		t.Fatalf("IsTOTPEnabled = (%v, %v), want (true, nil)", enabled, err)
	}
}

// ── TOTPStatus ───────────────────────────────────────────────────────────

func TestTOTPStatus_Unauthenticated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mfa/totp/status", nil)
	rec := httptest.NewRecorder()
	TOTPStatus(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestTOTPStatus_FalseThenTrue(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-status-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mfa/totp/status", nil)
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	TOTPStatus(d)(rec, req)
	var resp map[string]bool
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["enabled"] {
		t.Fatal("expected enabled=false before enrollment")
	}

	setupID, secret, _, err := mfa.BeginTOTPSetup(context.Background(), pool, userID, username)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if _, err := mfa.ConfirmTOTPSetup(context.Background(), pool, userID, setupID, totpGenCode(t, secret), 4); err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/mfa/totp/status", nil)
	req2 = withClaimsSub(req2, username)
	rec2 := httptest.NewRecorder()
	TOTPStatus(d)(rec2, req2)
	var resp2 map[string]bool
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
	if !resp2["enabled"] {
		t.Fatal("expected enabled=true after enrollment")
	}
}

// ── DisableTOTP ──────────────────────────────────────────────────────────

func TestDisableTOTP_Unauthenticated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"code":"123456"}`))
	rec := httptest.NewRecorder()
	DisableTOTP(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDisableTOTP_NotEnabled(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-disable-notenabled-%d", time.Now().UnixNano())
	createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"code":"123456"}`))
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	DisableTOTP(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestDisableTOTP_WrongCode_SessionAloneInsufficient is the core security
// regression test for the "hijacked session can't downgrade MFA" invariant:
// a validly authenticated request without a correct current TOTP/backup
// code must NOT be able to disable TOTP.
func TestDisableTOTP_WrongCode_SessionAloneInsufficient(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-disable-wrongcode-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)
	setupID, secret, _, err := mfa.BeginTOTPSetup(context.Background(), pool, userID, username)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if _, err := mfa.ConfirmTOTPSetup(context.Background(), pool, userID, setupID, totpGenCode(t, secret), 4); err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(`{"code":"000000"}`))
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	DisableTOTP(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	enabled, _ := mfa.IsTOTPEnabled(context.Background(), pool, userID)
	if !enabled {
		t.Fatal("totp must remain enabled after a wrong-code disable attempt — session auth alone must not disable MFA")
	}
}

func TestDisableTOTP_CorrectCode_Succeeds(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-disable-ok-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)
	setupID, secret, _, err := mfa.BeginTOTPSetup(context.Background(), pool, userID, username)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if _, err := mfa.ConfirmTOTPSetup(context.Background(), pool, userID, setupID, totpGenCode(t, secret), 4); err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	body := fmt.Sprintf(`{"code":%q}`, totpGenCode(t, secret))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/disable", strings.NewReader(body))
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	DisableTOTP(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	enabled, _ := mfa.IsTOTPEnabled(context.Background(), pool, userID)
	if enabled {
		t.Fatal("totp should be disabled after a correct-code disable request")
	}
}

// ── Login step-up + VerifyTOTPLogin ─────────────────────────────────────

// TestLogin_WithTOTPEnabled_WithholdsTokenAndReturnsChallenge is the core
// two-phase-login regression test: password auth alone must not issue a
// token once TOTP is enabled.
func TestLogin_WithTOTPEnabled_WithholdsTokenAndReturnsChallenge(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-login-%d", time.Now().UnixNano())
	u := createTestAuthorizeUser(t, d, username)
	setupID, secret, _, err := mfa.BeginTOTPSetup(context.Background(), pool, u.ID, username)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if _, err := mfa.ConfirmTOTPSetup(context.Background(), pool, u.ID, setupID, totpGenCode(t, secret), 4); err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	body := fmt.Sprintf(`{"username":%q,"password":%q}`, username, testPassword)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	Login(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["access_token"] != nil {
		t.Fatal("Login must not issue an access_token when TOTP is enabled — password auth alone is insufficient")
	}
	if mfaRequired, _ := resp["mfa_required"].(bool); !mfaRequired {
		t.Fatalf("expected mfa_required=true in response: %+v", resp)
	}
	if resp["challenge_id"] == nil || resp["challenge_id"] == "" {
		t.Fatalf("expected non-empty challenge_id in response: %+v", resp)
	}
}

func TestLogin_WithoutTOTP_IssuesTokenDirectly(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-login-none-%d", time.Now().UnixNano())
	createTestAuthorizeUser(t, d, username)

	body := fmt.Sprintf(`{"username":%q,"password":%q}`, username, testPassword)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	Login(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Fatalf("expected access_token when totp is not enabled: %+v", resp)
	}
}

// TestVerifyTOTPLogin_FullFlow exercises Login -> challenge -> VerifyTOTPLogin
// end to end, proving the two-phase flow actually issues a token on a
// correct second-factor code.
func TestVerifyTOTPLogin_FullFlow(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-login-full-%d", time.Now().UnixNano())
	u := createTestAuthorizeUser(t, d, username)
	setupID, secret, _, err := mfa.BeginTOTPSetup(context.Background(), pool, u.ID, username)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if _, err := mfa.ConfirmTOTPSetup(context.Background(), pool, u.ID, setupID, totpGenCode(t, secret), 4); err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	loginBody := fmt.Sprintf(`{"username":%q,"password":%q}`, username, testPassword)
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	Login(d)(loginRec, loginReq)
	var loginResp map[string]any
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginResp); err != nil {
		t.Fatalf("unmarshal login resp: %v", err)
	}
	challengeID, _ := loginResp["challenge_id"].(string)
	if challengeID == "" {
		t.Fatalf("expected challenge_id from login: %+v", loginResp)
	}

	verifyBody := fmt.Sprintf(`{"challenge_id":%q,"code":%q}`, challengeID, totpGenCode(t, secret))
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/login/verify", strings.NewReader(verifyBody))
	verifyRec := httptest.NewRecorder()
	VerifyTOTPLogin(d)(verifyRec, verifyReq)

	if verifyRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", verifyRec.Code, http.StatusOK, verifyRec.Body.String())
	}
	var verifyResp map[string]any
	if err := json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp); err != nil {
		t.Fatalf("unmarshal verify resp: %v", err)
	}
	if verifyResp["access_token"] == nil || verifyResp["access_token"] == "" {
		t.Fatalf("expected access_token after successful totp verify: %+v", verifyResp)
	}
}

func TestVerifyTOTPLogin_WrongChallenge_Rejected(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	body := `{"challenge_id":"00000000-0000-0000-0000-000000000000","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/login/verify", strings.NewReader(body))
	rec := httptest.NewRecorder()
	VerifyTOTPLogin(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestVerifyTOTPLogin_WrongCode_ChallengeSurvivesForRetry proves a mistyped
// code doesn't burn the login challenge — the user can retry within the
// challenge's validity window rather than restarting the whole login.
func TestVerifyTOTPLogin_WrongCode_ChallengeSurvivesForRetry(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-login-retry-%d", time.Now().UnixNano())
	u := createTestAuthorizeUser(t, d, username)
	setupID, secret, _, err := mfa.BeginTOTPSetup(context.Background(), pool, u.ID, username)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	if _, err := mfa.ConfirmTOTPSetup(context.Background(), pool, u.ID, setupID, totpGenCode(t, secret), 4); err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}
	challengeID, err := mfa.CreateTOTPLoginChallenge(context.Background(), pool, u.ID)
	if err != nil {
		t.Fatalf("CreateTOTPLoginChallenge: %v", err)
	}

	wrongBody := fmt.Sprintf(`{"challenge_id":%q,"code":"000000"}`, challengeID)
	wrongReq := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/login/verify", strings.NewReader(wrongBody))
	wrongRec := httptest.NewRecorder()
	VerifyTOTPLogin(d)(wrongRec, wrongReq)
	if wrongRec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: status = %d, want %d", wrongRec.Code, http.StatusUnauthorized)
	}

	rightBody := fmt.Sprintf(`{"challenge_id":%q,"code":%q}`, challengeID, totpGenCode(t, secret))
	rightReq := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/login/verify", strings.NewReader(rightBody))
	rightRec := httptest.NewRecorder()
	VerifyTOTPLogin(d)(rightRec, rightReq)
	if rightRec.Code != http.StatusOK {
		t.Fatalf("retry with correct code: status = %d, want %d; body=%s", rightRec.Code, http.StatusOK, rightRec.Body.String())
	}
}

// TestVerifyTOTPLogin_BackupCodeFallback proves a login can be completed
// with a backup code when the authenticator device is unavailable, and that
// the backup code is consumed (single-use) by doing so.
func TestVerifyTOTPLogin_BackupCodeFallback(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("totp-login-backup-%d", time.Now().UnixNano())
	u := createTestAuthorizeUser(t, d, username)
	setupID, secret, _, err := mfa.BeginTOTPSetup(context.Background(), pool, u.ID, username)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	backupCodes, err := mfa.ConfirmTOTPSetup(context.Background(), pool, u.ID, setupID, totpGenCode(t, secret), 4)
	if err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}

	challengeID, err := mfa.CreateTOTPLoginChallenge(context.Background(), pool, u.ID)
	if err != nil {
		t.Fatalf("CreateTOTPLoginChallenge: %v", err)
	}

	body := fmt.Sprintf(`{"challenge_id":%q,"code":%q}`, challengeID, backupCodes[0])
	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/login/verify", strings.NewReader(body))
	rec := httptest.NewRecorder()
	VerifyTOTPLogin(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// The backup code must now be single-use: a second login attempt with
	// the same code (fresh challenge) must fail.
	challengeID2, err := mfa.CreateTOTPLoginChallenge(context.Background(), pool, u.ID)
	if err != nil {
		t.Fatalf("CreateTOTPLoginChallenge (2nd): %v", err)
	}
	body2 := fmt.Sprintf(`{"challenge_id":%q,"code":%q}`, challengeID2, backupCodes[0])
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/totp/login/verify", strings.NewReader(body2))
	rec2 := httptest.NewRecorder()
	VerifyTOTPLogin(d)(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replayed backup code: status = %d, want %d — a used backup code must not work twice", rec2.Code, http.StatusUnauthorized)
	}
}
