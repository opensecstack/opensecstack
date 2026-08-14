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

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/mfa"
	"github.com/opensecstack/sinauth/internal/token"
)

// webauthnTestDeps extends testDeps with a real *webauthn.WebAuthn instance,
// an Issuer (needed by FinishWebAuthnLogin), and a fresh fakeSMSProvider.
func webauthnTestDeps(t *testing.T, pool *pgxpool.Pool) (Deps, *fakeSMSProvider) {
	t.Helper()
	d := testDeps(t, pool)
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "SIN Test",
		RPID:          "sinauth.test",
		RPOrigins:     []string{"https://sinauth.test"},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	d.WebAuthn = wa
	d.Issuer = token.NewIssuer(testRSAKey(t), "test-kid", "https://sinauth.test")
	sms := &fakeSMSProvider{}
	d.SMS = sms
	return d, sms
}

func createTestWAUser(t *testing.T, d Deps, username string) (userID string) {
	t.Helper()
	u := createTestAuthorizeUser(t, d, username)
	return u.ID
}

func insertDummyCredential(t *testing.T, pool *pgxpool.Pool, userID, credName string) []byte {
	t.Helper()
	credID := []byte(fmt.Sprintf("cred-%d", time.Now().UnixNano()))
	_, err := pool.Exec(context.Background(),
		`INSERT INTO webauthn_credentials (user_id, credential_id, public_key, name)
		 VALUES ($1,$2,$3,$4)`,
		userID, credID, []byte("fake-public-key"), credName,
	)
	if err != nil {
		t.Fatalf("insert dummy credential: %v", err)
	}
	return credID
}

// ── BeginWebAuthnRegister ────────────────────────────────────────────────

func TestBeginWebAuthnRegister_Unauthenticated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/register/begin", nil)
	rec := httptest.NewRecorder()
	BeginWebAuthnRegister(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestBeginWebAuthnRegister_Success_StoresSession(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	userID := createTestWAUser(t, d, fmt.Sprintf("wa-begin-reg-%d", time.Now().UnixNano()))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/register/begin", nil)
	req = withClaimsSub(req, mustUsername(t, pool, userID))
	rec := httptest.NewRecorder()
	BeginWebAuthnRegister(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM webauthn_sessions WHERE user_id=$1`, userID,
	).Scan(&count); err != nil {
		t.Fatalf("query sessions: %v", err)
	}
	if count != 1 {
		t.Fatalf("webauthn_sessions rows = %d, want 1", count)
	}
}

// ── FinishWebAuthnRegister ───────────────────────────────────────────────

func TestFinishWebAuthnRegister_Unauthenticated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/register/finish", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	FinishWebAuthnRegister(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestFinishWebAuthnRegister_NoActiveSession(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	userID := createTestWAUser(t, d, fmt.Sprintf("wa-finish-reg-nosess-%d", time.Now().UnixNano()))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/register/finish", strings.NewReader(`{}`))
	req = withClaimsSub(req, mustUsername(t, pool, userID))
	rec := httptest.NewRecorder()
	FinishWebAuthnRegister(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestFinishWebAuthnRegister_MalformedAttestation_Rejected(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("wa-finish-reg-bad-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)

	// Begin a real registration ceremony to create a session, then complete
	// it with a garbage body — the ceremony's cryptographic verification
	// must reject it rather than accept it or panic.
	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/register/begin", nil)
	beginReq = withClaimsSub(beginReq, username)
	beginRec := httptest.NewRecorder()
	BeginWebAuthnRegister(d)(beginRec, beginReq)
	if beginRec.Code != http.StatusOK {
		t.Fatalf("begin registration: status = %d, body=%s", beginRec.Code, beginRec.Body.String())
	}

	finishReq := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/register/finish", strings.NewReader(`{"not":"a valid attestation response"}`))
	finishReq.Header.Set("Content-Type", "application/json")
	finishReq = withClaimsSub(finishReq, username)
	finishRec := httptest.NewRecorder()
	FinishWebAuthnRegister(d)(finishRec, finishReq)

	if finishRec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (registration must be rejected, not accepted); body=%s", finishRec.Code, http.StatusBadRequest, finishRec.Body.String())
	}

	_ = userID
}

// ── BeginWebAuthnLogin ────────────────────────────────────────────────────

func TestBeginWebAuthnLogin_MissingUsername(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/login/begin", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	BeginWebAuthnLogin(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestBeginWebAuthnLogin_UnknownUser(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/login/begin", strings.NewReader(`{"username":"does-not-exist"}`))
	rec := httptest.NewRecorder()
	BeginWebAuthnLogin(d)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestBeginWebAuthnLogin_NoPasskeysRegistered(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("wa-login-nopasskey-%d", time.Now().UnixNano())
	createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/login/begin", strings.NewReader(fmt.Sprintf(`{"username":%q}`, username)))
	rec := httptest.NewRecorder()
	BeginWebAuthnLogin(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestBeginWebAuthnLogin_WithPasskey_Success(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("wa-login-haspasskey-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)
	insertDummyCredential(t, pool, userID, "My Key")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/login/begin", strings.NewReader(fmt.Sprintf(`{"username":%q}`, username)))
	rec := httptest.NewRecorder()
	BeginWebAuthnLogin(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM webauthn_sessions WHERE user_id=$1`, userID,
	).Scan(&count); err != nil {
		t.Fatalf("query sessions: %v", err)
	}
	if count != 1 {
		t.Fatalf("webauthn_sessions rows = %d, want 1", count)
	}
}

// ── FinishWebAuthnLogin ───────────────────────────────────────────────────

func TestFinishWebAuthnLogin_MissingUsername(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/login/finish", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	FinishWebAuthnLogin(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestFinishWebAuthnLogin_UnknownUser(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/login/finish?username=does-not-exist", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	FinishWebAuthnLogin(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestFinishWebAuthnLogin_NoActiveSession(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("wa-finish-login-nosess-%d", time.Now().UnixNano())
	createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/login/finish?username="+username, strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	FinishWebAuthnLogin(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestFinishWebAuthnLogin_MalformedAssertion_Rejected(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("wa-finish-login-bad-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)
	insertDummyCredential(t, pool, userID, "My Key")

	beginReq := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/login/begin", strings.NewReader(fmt.Sprintf(`{"username":%q}`, username)))
	beginRec := httptest.NewRecorder()
	BeginWebAuthnLogin(d)(beginRec, beginReq)
	if beginRec.Code != http.StatusOK {
		t.Fatalf("begin login: status = %d, body=%s", beginRec.Code, beginRec.Body.String())
	}

	finishReq := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/webauthn/login/finish?username="+username, strings.NewReader(`{"not":"a valid assertion"}`))
	finishReq.Header.Set("Content-Type", "application/json")
	finishRec := httptest.NewRecorder()
	FinishWebAuthnLogin(d)(finishRec, finishReq)

	// A forged/garbled assertion must never be accepted as a successful login.
	if finishRec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (must reject, not authenticate); body=%s", finishRec.Code, http.StatusUnauthorized, finishRec.Body.String())
	}
}

// ── ListWebAuthnCredentials / DeleteWebAuthnCredential ──────────────────────

func TestListWebAuthnCredentials_Unauthenticated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mfa/webauthn/credentials", nil)
	rec := httptest.NewRecorder()
	ListWebAuthnCredentials(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestListWebAuthnCredentials_EmptyThenPopulated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("wa-list-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/mfa/webauthn/credentials", nil)
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	ListWebAuthnCredentials(d)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var creds []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &creds); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("expected 0 credentials, got %d", len(creds))
	}

	insertDummyCredential(t, pool, userID, "Yubikey")

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/mfa/webauthn/credentials", nil)
	req2 = withClaimsSub(req2, username)
	rec2 := httptest.NewRecorder()
	ListWebAuthnCredentials(d)(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec2.Code, http.StatusOK)
	}
	var creds2 []map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &creds2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(creds2) != 1 || creds2[0]["name"] != "Yubikey" {
		t.Fatalf("credentials = %+v, want 1 entry named Yubikey", creds2)
	}
}

func TestDeleteWebAuthnCredential_Unauthenticated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/mfa/webauthn/credentials/abc", nil)
	req.SetPathValue("id", "abc")
	rec := httptest.NewRecorder()
	DeleteWebAuthnCredential(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDeleteWebAuthnCredential_RemovesOwnCredentialOnly(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	usernameA := fmt.Sprintf("wa-del-a-%d", time.Now().UnixNano())
	usernameB := fmt.Sprintf("wa-del-b-%d", time.Now().UnixNano())
	userA := createTestWAUser(t, d, usernameA)
	userB := createTestWAUser(t, d, usernameB)
	credA := insertDummyCredential(t, pool, userA, "A's key")
	credBID := insertDummyCredential(t, pool, userB, "B's key")
	_ = credBID

	// A must not be able to delete B's credential by guessing/observing its id.
	var credBBase64 string
	if err := pool.QueryRow(context.Background(),
		`SELECT encode(credential_id,'base64') FROM webauthn_credentials WHERE user_id=$1`, userB,
	).Scan(&credBBase64); err != nil {
		t.Fatalf("query B credential id: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/mfa/webauthn/credentials/"+credBBase64, nil)
	req.SetPathValue("id", credBBase64)
	req = withClaimsSub(req, usernameA)
	rec := httptest.NewRecorder()
	DeleteWebAuthnCredential(d)(rec, req)

	if rec.Code != http.StatusNoContent {
		// The handler always reports success (scoped DELETE with no rows
		// affected is not an error) — assert B's credential is still there.
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	var stillThere int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM webauthn_credentials WHERE user_id=$1`, userB,
	).Scan(&stillThere); err != nil {
		t.Fatalf("query: %v", err)
	}
	if stillThere != 1 {
		t.Fatalf("B's credential was deleted by A's request — IDOR: cross-user credential deletion is possible")
	}

	// Now A deletes their own credential — must succeed.
	var credABase64 string
	if err := pool.QueryRow(context.Background(),
		`SELECT encode(credential_id,'base64') FROM webauthn_credentials WHERE user_id=$1`, userA,
	).Scan(&credABase64); err != nil {
		t.Fatalf("query A credential id: %v", err)
	}
	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/mfa/webauthn/credentials/"+credABase64, nil)
	req2.SetPathValue("id", credABase64)
	req2 = withClaimsSub(req2, usernameA)
	rec2 := httptest.NewRecorder()
	DeleteWebAuthnCredential(d)(rec2, req2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec2.Code, http.StatusNoContent)
	}
	var aGone int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM webauthn_credentials WHERE user_id=$1`, userA,
	).Scan(&aGone); err != nil {
		t.Fatalf("query: %v", err)
	}
	if aGone != 0 {
		t.Fatal("A's own credential should have been deleted")
	}
	_ = credA
}

func TestDeleteWebAuthnCredential_MissingID(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("wa-del-missing-id-%d", time.Now().UnixNano())
	createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/mfa/webauthn/credentials/", nil)
	req.SetPathValue("id", "")
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	DeleteWebAuthnCredential(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// ── SendSMSOTP / VerifySMSOTP ────────────────────────────────────────────

func TestSendSMSOTP_Unauthenticated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/sms/send", nil)
	rec := httptest.NewRecorder()
	SendSMSOTP(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSendSMSOTP_NoPhoneOnFile(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("sms-nophone-%d", time.Now().UnixNano())
	createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/sms/send", nil)
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	SendSMSOTP(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestSendSMSOTP_Success(t *testing.T) {
	pool := requireDB(t)
	d, sms := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("sms-ok-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)
	if _, err := pool.Exec(context.Background(), `UPDATE users SET phone=$1 WHERE id=$2`, "+15551234567", userID); err != nil {
		t.Fatalf("set phone: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/sms/send", nil)
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	SendSMSOTP(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(sms.sentTo) != 1 || sms.sentTo[0] != "+15551234567" {
		t.Fatalf("SMS provider was not invoked with the user's phone: %+v", sms.sentTo)
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sms_otp WHERE user_id=$1 AND used=false`, userID).Scan(&count); err != nil {
		t.Fatalf("query sms_otp: %v", err)
	}
	if count != 1 {
		t.Fatalf("sms_otp unused rows = %d, want 1", count)
	}
}

func TestSendSMSOTP_ProviderFailure(t *testing.T) {
	pool := requireDB(t)
	d, sms := webauthnTestDeps(t, pool)
	sms.fail = true
	username := fmt.Sprintf("sms-fail-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)
	if _, err := pool.Exec(context.Background(), `UPDATE users SET phone=$1 WHERE id=$2`, "+15551234567", userID); err != nil {
		t.Fatalf("set phone: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/sms/send", nil)
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	SendSMSOTP(d)(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestVerifySMSOTP_Unauthenticated(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/sms/verify", strings.NewReader(`{"code":"123456"}`))
	rec := httptest.NewRecorder()
	VerifySMSOTP(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestVerifySMSOTP_MissingCode(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("sms-verify-missing-%d", time.Now().UnixNano())
	createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/sms/verify", strings.NewReader(`{}`))
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	VerifySMSOTP(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestVerifySMSOTP_InvalidCode(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("sms-verify-invalid-%d", time.Now().UnixNano())
	createTestWAUser(t, d, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/sms/verify", strings.NewReader(`{"code":"000000"}`))
	req = withClaimsSub(req, username)
	rec := httptest.NewRecorder()
	VerifySMSOTP(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestVerifySMSOTP_ValidCode_IsSingleUse is the core security regression
// test for OTP replay: a code that was just successfully verified must not
// verify again.
func TestVerifySMSOTP_ValidCode_IsSingleUse(t *testing.T) {
	pool := requireDB(t)
	d, _ := webauthnTestDeps(t, pool)
	username := fmt.Sprintf("sms-verify-replay-%d", time.Now().UnixNano())
	userID := createTestWAUser(t, d, username)
	if err := mfa.StoreSMSOTP(context.Background(), pool, userID, "+15551234567", "654321"); err != nil {
		t.Fatalf("StoreSMSOTP: %v", err)
	}

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/sms/verify", strings.NewReader(`{"code":"654321"}`))
	req1 = withClaimsSub(req1, username)
	rec1 := httptest.NewRecorder()
	VerifySMSOTP(d)(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first verify: status = %d, want %d; body=%s", rec1.Code, http.StatusOK, rec1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/mfa/sms/verify", strings.NewReader(`{"code":"654321"}`))
	req2 = withClaimsSub(req2, username)
	rec2 := httptest.NewRecorder()
	VerifySMSOTP(d)(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replay verify: status = %d, want %d — a used OTP must not verify again", rec2.Code, http.StatusUnauthorized)
	}
}

// mustUsername resolves a user's username from their id, for tests that
// have a userID (from createTestWAUser) but need a username for
// withClaimsSub / request bodies.
func mustUsername(t *testing.T, pool *pgxpool.Pool, userID string) string {
	t.Helper()
	var username string
	if err := pool.QueryRow(context.Background(), `SELECT username FROM users WHERE id=$1`, userID).Scan(&username); err != nil {
		t.Fatalf("mustUsername: %v", err)
	}
	return username
}
