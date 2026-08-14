//go:build integration

package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/sinauth/internal/email"
	"github.com/opensecstack/sinauth/internal/token"
	"github.com/opensecstack/sinauth/internal/user"
)

func doJSONRequest(t *testing.T, h http.HandlerFunc, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func authTestDeps(t *testing.T) Deps {
	t.Helper()
	pool := requireDB(t)
	d := testDeps(t, pool)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	d.Issuer = token.NewIssuer(key, "test-kid", "https://sinauth.test")
	d.Cfg.AccessTokenTTL = time.Hour
	d.Mailer = email.New(email.Config{}) // Host == "" -> SendVerification/SendPasswordReset are no-ops
	return d
}

func createAuthTestUser(t *testing.T, d Deps, username, password string) *user.User {
	t.Helper()
	u, err := d.UserSvc.Create(context.Background(), username, username+"@example.com", password, "Test User")
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID) })
	return u
}

// -------------------- Login --------------------

func TestLogin_WrongPassword_Returns401(t *testing.T) {
	d := authTestDeps(t)
	username := fmt.Sprintf("login-wrongpw-%d", time.Now().UnixNano())
	createAuthTestUser(t, d, username, "correct horse battery staple")

	body := fmt.Sprintf(`{"username":%q,"password":"definitely-wrong"}`, username)
	rec := doJSONRequest(t, Login(d), http.MethodPost, "/api/v1/auth/login", body)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["access_token"] != "" {
		t.Fatalf("no access_token should be present on a failed login: %v", resp)
	}
}

func TestLogin_UnknownUsername_Returns401WithSameErrorAsWrongPassword(t *testing.T) {
	d := authTestDeps(t)

	bodyUnknown := fmt.Sprintf(`{"username":"no-such-user-%d","password":"whatever"}`, time.Now().UnixNano())
	recUnknown := doJSONRequest(t, Login(d), http.MethodPost, "/api/v1/auth/login", bodyUnknown)

	username := fmt.Sprintf("login-enum-%d", time.Now().UnixNano())
	createAuthTestUser(t, d, username, "correct horse battery staple")
	bodyWrongPW := fmt.Sprintf(`{"username":%q,"password":"definitely-wrong"}`, username)
	recWrongPW := doJSONRequest(t, Login(d), http.MethodPost, "/api/v1/auth/login", bodyWrongPW)

	if recUnknown.Code != recWrongPW.Code {
		t.Fatalf("status codes differ between unknown-username (%d) and wrong-password (%d); "+
			"a status/response difference is a username-enumeration oracle", recUnknown.Code, recWrongPW.Code)
	}
	if recUnknown.Body.String() != recWrongPW.Body.String() {
		t.Fatalf("response bodies differ between unknown-username (%s) and wrong-password (%s); "+
			"a body difference is a username-enumeration oracle", recUnknown.Body.String(), recWrongPW.Body.String())
	}
}

func TestLogin_CorrectCredentials_ReturnsAccessToken(t *testing.T) {
	d := authTestDeps(t)
	username := fmt.Sprintf("login-ok-%d", time.Now().UnixNano())
	password := "correct horse battery staple"
	createAuthTestUser(t, d, username, password)

	body := fmt.Sprintf(`{"username":%q,"password":%q}`, username, password)
	rec := doJSONRequest(t, Login(d), http.MethodPost, "/api/v1/auth/login", body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Fatalf("expected access_token in response, got %v", resp)
	}
	if resp["sub"] != username {
		t.Errorf("sub = %v, want %q", resp["sub"], username)
	}
}

func TestLogin_MalformedJSON_Returns400(t *testing.T) {
	d := authTestDeps(t)
	rec := doJSONRequest(t, Login(d), http.MethodPost, "/api/v1/auth/login", `{not-json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// -------------------- Register --------------------

func TestRegister_ShortPassword_Rejected(t *testing.T) {
	d := authTestDeps(t)
	username := fmt.Sprintf("reg-shortpw-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"username":%q,"email":%q,"password":"short1","display_name":"X"}`, username, username+"@example.com")
	rec := doJSONRequest(t, Register(d), http.MethodPost, "/api/v1/auth/register", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestRegister_InvalidEmail_Rejected(t *testing.T) {
	d := authTestDeps(t)
	username := fmt.Sprintf("reg-bademail-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"username":%q,"email":"not-an-email","password":"longenoughpassword","display_name":"X"}`, username)
	rec := doJSONRequest(t, Register(d), http.MethodPost, "/api/v1/auth/register", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestRegister_EmptyUsername_Rejected(t *testing.T) {
	d := authTestDeps(t)
	body := `{"username":"","email":"x@example.com","password":"longenoughpassword","display_name":"X"}`
	rec := doJSONRequest(t, Register(d), http.MethodPost, "/api/v1/auth/register", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestRegister_DuplicateUsername_Returns409(t *testing.T) {
	d := authTestDeps(t)
	username := fmt.Sprintf("reg-dup-%d", time.Now().UnixNano())
	createAuthTestUser(t, d, username, "longenoughpassword")

	body := fmt.Sprintf(`{"username":%q,"email":%q,"password":"anotherlongpassword","display_name":"Y"}`, username, username+"-2@example.com")
	rec := doJSONRequest(t, Register(d), http.MethodPost, "/api/v1/auth/register", body)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

func TestRegister_Success_Returns201(t *testing.T) {
	d := authTestDeps(t)
	username := fmt.Sprintf("reg-ok-%d", time.Now().UnixNano())
	body := fmt.Sprintf(`{"username":%q,"email":%q,"password":"longenoughpassword","display_name":"New User"}`, username, username+"@example.com")
	rec := doJSONRequest(t, Register(d), http.MethodPost, "/api/v1/auth/register", body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	u, err := d.UserSvc.GetByUsername(context.Background(), username)
	if err != nil {
		t.Fatalf("expected user to be created: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID) })
}

// -------------------- ForgotPassword --------------------

// The forgot-password response must be identical whether or not the email
// exists — this is the account-enumeration guard the handler comment claims;
// this test proves it holds for both status and body.
func TestForgotPassword_UnknownEmail_SameResponseAsKnownEmail(t *testing.T) {
	d := authTestDeps(t)
	username := fmt.Sprintf("forgot-known-%d", time.Now().UnixNano())
	u := createAuthTestUser(t, d, username, "longenoughpassword")

	recKnown := doJSONRequest(t, ForgotPassword(d), http.MethodPost, "/api/v1/auth/forgot-password",
		fmt.Sprintf(`{"email":%q}`, u.Email))
	recUnknown := doJSONRequest(t, ForgotPassword(d), http.MethodPost, "/api/v1/auth/forgot-password",
		`{"email":"no-such-account@example.com"}`)

	if recKnown.Code != recUnknown.Code {
		t.Fatalf("status differs: known=%d unknown=%d (account-enumeration oracle)", recKnown.Code, recUnknown.Code)
	}
	if recKnown.Body.String() != recUnknown.Body.String() {
		t.Fatalf("body differs: known=%s unknown=%s (account-enumeration oracle)", recKnown.Body.String(), recUnknown.Body.String())
	}
	if recKnown.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recKnown.Code, http.StatusOK)
	}
}

// -------------------- ResetPassword --------------------

func TestResetPassword_InvalidToken_Rejected(t *testing.T) {
	d := authTestDeps(t)
	body := `{"token":"not-a-real-token","new_password":"newlongenoughpassword"}`
	rec := doJSONRequest(t, ResetPassword(d), http.MethodPost, "/api/v1/auth/reset-password", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestResetPassword_ShortNewPassword_Rejected(t *testing.T) {
	d := authTestDeps(t)
	body := `{"token":"whatever","new_password":"short"}`
	rec := doJSONRequest(t, ResetPassword(d), http.MethodPost, "/api/v1/auth/reset-password", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// A valid reset token actually changes the password: the old password must
// stop working and the new one must work afterward.
func TestResetPassword_ValidToken_ChangesPasswordAndInvalidatesOld(t *testing.T) {
	d := authTestDeps(t)
	username := fmt.Sprintf("reset-ok-%d", time.Now().UnixNano())
	oldPassword := "original-long-password"
	u := createAuthTestUser(t, d, username, oldPassword)

	token, err := d.UserSvc.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := d.UserSvc.StorePasswordResetToken(context.Background(), u.ID, token); err != nil {
		t.Fatalf("StorePasswordResetToken: %v", err)
	}

	newPassword := "brand-new-long-password"
	body := fmt.Sprintf(`{"token":%q,"new_password":%q}`, token, newPassword)
	rec := doJSONRequest(t, ResetPassword(d), http.MethodPost, "/api/v1/auth/reset-password", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if _, err := d.UserSvc.Authenticate(context.Background(), username, oldPassword); err == nil {
		t.Fatalf("old password must no longer authenticate after reset")
	}
	if _, err := d.UserSvc.Authenticate(context.Background(), username, newPassword); err != nil {
		t.Fatalf("new password must authenticate after reset: %v", err)
	}

	// The token must be single-use.
	body2 := fmt.Sprintf(`{"token":%q,"new_password":"yet-another-long-password"}`, token)
	rec2 := doJSONRequest(t, ResetPassword(d), http.MethodPost, "/api/v1/auth/reset-password", body2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("reused reset token: status = %d, want %d (token must be single-use)", rec2.Code, http.StatusBadRequest)
	}
}
