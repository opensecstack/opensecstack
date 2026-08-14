//go:build integration

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/token"
)

// socialTestDeps extends testDeps (defined in authorize_test.go) with the
// Issuer needed by the social-login success path (direct dashboard login and
// the OAuth-completion redirect both mint an access token).
func socialTestDeps(t *testing.T, pool *pgxpool.Pool) Deps {
	t.Helper()
	d := testDeps(t, pool)
	key := testRSAKey(t)
	d.Issuer = token.NewIssuer(key, "test-kid", "https://sinauth.test")
	return d
}

// ── generateState / cookie helpers ──────────────────────────────────────────

func TestGenerateState_UniqueAndDecodable(t *testing.T) {
	s1, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	s2, err := generateState()
	if err != nil {
		t.Fatalf("generateState: %v", err)
	}
	if s1 == "" || s2 == "" {
		t.Fatal("generateState returned empty string")
	}
	if s1 == s2 {
		t.Fatal("generateState returned the same value twice — not random")
	}
	b, err := base64.RawURLEncoding.DecodeString(s1)
	if err != nil {
		t.Fatalf("state is not valid base64url: %v", err)
	}
	if len(b) != 16 {
		t.Fatalf("decoded state length = %d, want 16 bytes", len(b))
	}
}

func TestStateCookie_RoundTrip(t *testing.T) {
	rec := httptest.NewRecorder()
	setStateCookie(rec, "the-state-value")

	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	if !verifyStateCookie(req, "the-state-value") {
		t.Fatal("verifyStateCookie should succeed when state matches the cookie")
	}
	if verifyStateCookie(req, "wrong-state") {
		t.Fatal("verifyStateCookie must fail when the supplied state does not match the cookie (CSRF protection)")
	}
}

func TestVerifyStateCookie_NoCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback?state=anything", nil)
	if verifyStateCookie(req, "anything") {
		t.Fatal("verifyStateCookie must fail when no state cookie was ever set")
	}
}

func TestVerifyStateCookie_EmptyCookieValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	req.AddCookie(&http.Cookie{Name: "sinauth_oauth_state", Value: ""})
	if verifyStateCookie(req, "") {
		t.Fatal("verifyStateCookie must reject an empty state even if both sides are empty")
	}
}

func TestClearStateCookie_Expires(t *testing.T) {
	rec := httptest.NewRecorder()
	clearStateCookie(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Name != "sinauth_oauth_state" {
		t.Fatalf("cookie name = %q, want sinauth_oauth_state", cookies[0].Name)
	}
	if cookies[0].MaxAge >= 0 {
		t.Fatalf("MaxAge = %d, want negative (immediate expiry)", cookies[0].MaxAge)
	}
}

func TestRedirectWithToken_DefaultSiteURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rec := httptest.NewRecorder()
	redirectWithToken(rec, req, "", "tok123")

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc := rec.Header().Get("Location")
	if loc != "http://localhost:5173/?social_token=tok123" {
		t.Fatalf("Location = %q, want default site URL with token", loc)
	}
}

func TestRedirectWithToken_CustomSiteURL_TrimsTrailingSlash(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rec := httptest.NewRecorder()
	redirectWithToken(rec, req, "https://sin.to/", "abc")

	loc := rec.Header().Get("Location")
	if loc != "https://sin.to/?social_token=abc" {
		t.Fatalf("Location = %q, want trailing slash trimmed before appending query", loc)
	}
}

func TestSetOAuthReturnCookie_SetsWhenParamPresent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/google?oauth_return=eyJhIjoxfQ==", nil)
	rec := httptest.NewRecorder()
	setOAuthReturnCookie(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "sinauth_oauth_return" {
		t.Fatalf("expected sinauth_oauth_return cookie to be set, got %v", cookies)
	}
	if cookies[0].Value != "eyJhIjoxfQ==" {
		t.Fatalf("cookie value = %q, want the oauth_return param echoed back", cookies[0].Value)
	}
}

func TestSetOAuthReturnCookie_NoOpWhenParamAbsent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/auth/google", nil)
	rec := httptest.NewRecorder()
	setOAuthReturnCookie(rec, req)

	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("expected no cookie when oauth_return is absent, got %v", rec.Result().Cookies())
	}
}

// ── completeOAuthFromSocial ──────────────────────────────────────────────────

func TestCompleteOAuthFromSocial_NoCookie_ReturnsFalse(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rec := httptest.NewRecorder()

	if completeOAuthFromSocial(rec, req, d, "some-user-id") {
		t.Fatal("expected false when no oauth_return cookie is present")
	}
	if rec.Body.Len() != 0 {
		t.Fatal("handler must not write a response when it declines to handle (no cookie)")
	}
}

func TestCompleteOAuthFromSocial_MalformedBase64_ReturnsFalse(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	req.AddCookie(&http.Cookie{Name: "sinauth_oauth_return", Value: "not-valid-base64!!!"})
	rec := httptest.NewRecorder()

	if completeOAuthFromSocial(rec, req, d, "some-user-id") {
		t.Fatal("expected false when the cookie is not valid base64")
	}
}

func TestCompleteOAuthFromSocial_MalformedJSON_ReturnsFalse(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	req.AddCookie(&http.Cookie{Name: "sinauth_oauth_return", Value: base64.StdEncoding.EncodeToString([]byte("not json"))})
	rec := httptest.NewRecorder()

	if completeOAuthFromSocial(rec, req, d, "some-user-id") {
		t.Fatal("expected false when the decoded cookie is not valid JSON")
	}
}

func TestCompleteOAuthFromSocial_MissingClientOrRedirect_ReturnsFalse(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)

	cases := []oauthReturnParams{
		{ClientID: "", RedirectURI: "https://client.test/cb"},
		{ClientID: "some-client", RedirectURI: ""},
	}
	for i, p := range cases {
		raw, _ := json.Marshal(p)
		req := httptest.NewRequest(http.MethodGet, "/callback", nil)
		req.AddCookie(&http.Cookie{Name: "sinauth_oauth_return", Value: base64.StdEncoding.EncodeToString(raw)})
		rec := httptest.NewRecorder()

		if completeOAuthFromSocial(rec, req, d, "some-user-id") {
			t.Fatalf("case %d: expected false when client_id/redirect_uri is missing", i)
		}
	}
}

func TestCompleteOAuthFromSocial_Success_IssuesCodeAndRedirects(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("social-complete-%d", time.Now().UnixNano()))

	p := oauthReturnParams{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               "openid profile",
		State:               "client-state-xyz",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-1",
	}
	raw, _ := json.Marshal(p)
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	req.AddCookie(&http.Cookie{Name: "sinauth_oauth_return", Value: base64.StdEncoding.EncodeToString(raw)})
	rec := httptest.NewRecorder()

	handled := completeOAuthFromSocial(rec, req, d, u.ID)
	if !handled {
		t.Fatalf("expected true (handled); body=%s", rec.Body.String())
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("Location = %q, expected a code param", loc.String())
	}
	if loc.Query().Get("state") != "client-state-xyz" {
		t.Fatalf("state param = %q, want echoed client state", loc.Query().Get("state"))
	}

	// The consumed cookie must be cleared so it cannot be replayed.
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sinauth_oauth_return" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("sinauth_oauth_return cookie must be cleared after use (single-use)")
	}

	var storedUserID string
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id::text FROM authorization_codes WHERE code=$1`, code,
	).Scan(&storedUserID); err != nil {
		t.Fatalf("query stored code: %v", err)
	}
	if storedUserID != u.ID {
		t.Fatalf("stored user_id = %q, want %q", storedUserID, u.ID)
	}
}

func TestCompleteOAuthFromSocial_IssueAuthCodeError_Returns500(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("social-fk-fail-%d", time.Now().UnixNano()))

	// A client_id that does not exist violates the FK on authorization_codes,
	// forcing issueAuthCode to fail.
	p := oauthReturnParams{
		ClientID:    "does-not-exist-client",
		RedirectURI: "https://client.test/callback",
	}
	raw, _ := json.Marshal(p)
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	req.AddCookie(&http.Cookie{Name: "sinauth_oauth_return", Value: base64.StdEncoding.EncodeToString(raw)})
	rec := httptest.NewRecorder()

	handled := completeOAuthFromSocial(rec, req, d, u.ID)
	if !handled {
		t.Fatal("expected true (handled, even though it errored)")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// ── Google OAuth start/callback ─────────────────────────────────────────────

func TestGoogleOAuthStart_NotConfigured(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)
	d.Cfg.GoogleClientID = ""

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google", nil)
	rec := httptest.NewRecorder()
	GoogleOAuthStart(d)(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotImplemented)
	}
}

func TestGoogleOAuthStart_Configured_RedirectsWithState(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)
	d.Cfg.GoogleClientID = "google-client-id"
	d.Cfg.GoogleRedirectURI = "https://sinauth.test/api/v1/auth/google/callback"

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google", nil)
	rec := httptest.NewRecorder()
	GoogleOAuthStart(d)(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if !strings.HasPrefix(loc.String(), "https://accounts.google.com/o/oauth2/v2/auth?") {
		t.Fatalf("Location = %q, want Google's authorize endpoint", loc.String())
	}
	if loc.Query().Get("client_id") != "google-client-id" {
		t.Fatalf("client_id = %q, want google-client-id", loc.Query().Get("client_id"))
	}
	if loc.Query().Get("state") == "" {
		t.Fatal("state param must be set")
	}

	var stateCookieSet bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sinauth_oauth_state" && c.Value == loc.Query().Get("state") {
			stateCookieSet = true
		}
	}
	if !stateCookieSet {
		t.Fatal("sinauth_oauth_state cookie must be set to the same state used in the redirect URL")
	}
}

func TestGoogleOAuthCallback_InvalidState_Rejected(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)

	// No state cookie was ever set — this simulates a CSRF attempt or an
	// expired/tampered state param.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/callback?state=attacker-state&code=abc", nil)
	rec := httptest.NewRecorder()
	GoogleOAuthCallback(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestGoogleOAuthCallback_StateMismatch_Rejected(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/callback?state=state-b&code=abc", nil)
	req.AddCookie(&http.Cookie{Name: "sinauth_oauth_state", Value: "state-a"})
	rec := httptest.NewRecorder()
	GoogleOAuthCallback(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d — mismatched state must never be accepted", rec.Code, http.StatusBadRequest)
	}
}

func TestGoogleOAuthCallback_MissingCode_Rejected(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/callback?state=good-state", nil)
	req.AddCookie(&http.Cookie{Name: "sinauth_oauth_state", Value: "good-state"})
	rec := httptest.NewRecorder()
	GoogleOAuthCallback(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	// The state cookie must be cleared immediately after verification so a
	// captured/leaked state value cannot be replayed against this endpoint.
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sinauth_oauth_state" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("sinauth_oauth_state cookie must be cleared once verified (single use, replay protection)")
	}
}

// ── GitHub OAuth start/callback ─────────────────────────────────────────────

func TestGitHubOAuthStart_NotConfigured(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)
	d.Cfg.GitHubClientID = ""

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github", nil)
	rec := httptest.NewRecorder()
	GitHubOAuthStart(d)(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotImplemented)
	}
}

func TestGitHubOAuthStart_Configured_RedirectsWithState(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)
	d.Cfg.GitHubClientID = "github-client-id"
	d.Cfg.GitHubRedirectURI = "https://sinauth.test/api/v1/auth/github/callback"

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github", nil)
	rec := httptest.NewRecorder()
	GitHubOAuthStart(d)(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if !strings.HasPrefix(loc.String(), "https://github.com/login/oauth/authorize?") {
		t.Fatalf("Location = %q, want GitHub's authorize endpoint", loc.String())
	}
	if loc.Query().Get("client_id") != "github-client-id" {
		t.Fatalf("client_id = %q, want github-client-id", loc.Query().Get("client_id"))
	}
}

func TestGitHubOAuthCallback_InvalidState_Rejected(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github/callback?state=attacker&code=abc", nil)
	rec := httptest.NewRecorder()
	GitHubOAuthCallback(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestGitHubOAuthCallback_MissingCode_Rejected(t *testing.T) {
	pool := requireDB(t)
	d := socialTestDeps(t, pool)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github/callback?state=good", nil)
	req.AddCookie(&http.Cookie{Name: "sinauth_oauth_state", Value: "good"})
	rec := httptest.NewRecorder()
	GitHubOAuthCallback(d)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
