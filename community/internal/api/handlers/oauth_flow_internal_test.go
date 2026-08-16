package handlers

// HTTP-level and helper-function tests for the GitHub OAuth flow
// (oauth.go). Security focus: CSRF state validation, rejection of
// incomplete/failed upstream responses, and the find-or-create/account
// linking logic (tested against a real migrated Postgres instance so the
// "link by verified email" behaviour — a common OAuth account-takeover
// pitfall if done wrong — is actually exercised, not just assumed).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func githubTestCfg() *config.Config {
	return &config.Config{
		GitHubClientID:     "gh-client-id",
		GitHubClientSecret: "gh-client-secret",
		GitHubCallbackURL:  "https://example.test/api/v1/auth/github/callback",
		SiteURL:            "https://frontend.test",
		JWTSecret:          "unit-test-secret-unit-test-secret",
		JWTIssuer:          "test",
		TokenTTL:           3_600_000_000_000,
	}
}

// ---------------------------------------------------------------------------
// GitHubOAuthStart
// ---------------------------------------------------------------------------

func TestGitHubOAuthStart_SetsStateCookieAndRedirectsWithMatchingState(t *testing.T) {
	d := Deps{Cfg: githubTestCfg()}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github", nil)
	w := httptest.NewRecorder()

	GitHubOAuthStart(d)(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	var stateCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil || stateCookie.Value == "" {
		t.Fatal("expected non-empty oauth_state cookie")
	}
	if !stateCookie.HttpOnly {
		t.Error("oauth_state cookie must be HttpOnly")
	}
	if stateCookie.SameSite != http.SameSiteLaxMode {
		t.Error("oauth_state cookie must be SameSite=Lax")
	}
	if !stateCookie.Secure {
		t.Error("oauth_state cookie must be Secure outside dev mode")
	}

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("bad Location header: %v", err)
	}
	if got := loc.Query().Get("state"); got != stateCookie.Value {
		t.Errorf("redirect state %q does not match cookie state %q", got, stateCookie.Value)
	}
	if got := loc.Query().Get("client_id"); got != "gh-client-id" {
		t.Errorf("expected client_id=gh-client-id in redirect, got %q", got)
	}
}

func TestGitHubOAuthStart_DevMode_CookieNotSecure(t *testing.T) {
	cfg := githubTestCfg()
	cfg.DevMode = true
	d := Deps{Cfg: cfg}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github", nil)
	w := httptest.NewRecorder()

	GitHubOAuthStart(d)(w, req)

	for _, c := range w.Result().Cookies() {
		if c.Name == "oauth_state" && c.Secure {
			t.Error("expected non-Secure cookie in DevMode")
		}
	}
}

// ---------------------------------------------------------------------------
// GitHubOAuthCallback — CSRF / input validation branches (no network, no DB)
// ---------------------------------------------------------------------------

func githubCallbackReq(query string, stateCookie string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github/callback?"+query, nil)
	if stateCookie != "" {
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: stateCookie})
	}
	return req
}

func TestGitHubOAuthCallback_MissingStateCookie_RedirectsWithError(t *testing.T) {
	d := Deps{Cfg: githubTestCfg()}
	req := githubCallbackReq("state=abc&code=xyz", "")
	w := httptest.NewRecorder()

	GitHubOAuthCallback(d)(w, req)

	assertRedirectError(t, w, "missing state")
}

func TestGitHubOAuthCallback_StateMismatch_RedirectsWithError(t *testing.T) {
	d := Deps{Cfg: githubTestCfg()}
	req := githubCallbackReq("state=attacker-supplied&code=xyz", "cookie-value")
	w := httptest.NewRecorder()

	GitHubOAuthCallback(d)(w, req)

	assertRedirectError(t, w, "state mismatch")
}

// The state cookie must be single-use: a failed CSRF check (state mismatch)
// must clear it just like the success path does, so a rejected attempt
// cannot leave a still-valid state token sitting in the browser for the rest
// of its 10-minute MaxAge window to be replayed against a later authorize
// redirect. (This was previously NOT the case — see git history — the clear
// was moved ahead of the comparison as part of this test pass.)
func TestGitHubOAuthCallback_StateMismatch_ClearsCookie(t *testing.T) {
	d := Deps{Cfg: githubTestCfg()}
	req := githubCallbackReq("state=wrong&code=xyz", "right")
	w := httptest.NewRecorder()

	GitHubOAuthCallback(d)(w, req)

	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "oauth_state" {
			found = true
			if c.MaxAge >= 0 {
				t.Errorf("expected oauth_state cookie to be expired (MaxAge<0), got %d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("expected an oauth_state cookie clear directive even on state mismatch")
	}
}

func TestGitHubOAuthCallback_MissingCode_RedirectsWithError(t *testing.T) {
	d := Deps{Cfg: githubTestCfg()}
	req := githubCallbackReq("state=match", "match")
	w := httptest.NewRecorder()

	GitHubOAuthCallback(d)(w, req)

	assertRedirectError(t, w, "no code returned by GitHub")
}

// assertRedirectError checks that the handler redirected to
// frontendBase/oauth/callback?error=<msg>.
func assertRedirectError(t *testing.T, w *httptest.ResponseRecorder, wantMsgContains string) {
	t.Helper()
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/oauth/callback?error=") {
		t.Fatalf("expected error redirect, got Location=%q", loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad Location: %v", err)
	}
	got := u.Query().Get("error")
	if !strings.Contains(got, wantMsgContains) {
		t.Errorf("expected error message containing %q, got %q", wantMsgContains, got)
	}
}

// ---------------------------------------------------------------------------
// GitHubOAuthCallback — network-dependent branches (stubbed transport)
// ---------------------------------------------------------------------------

func jsonResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestGitHubOAuthCallback_TokenExchangeFails_RedirectsWithError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.String(), "github.com/login/oauth/access_token") {
			return jsonResp(200, `{"error":"bad_verification_code"}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))

	d := Deps{Cfg: githubTestCfg()}
	req := githubCallbackReq("state=match&code=abc123", "match")
	w := httptest.NewRecorder()

	GitHubOAuthCallback(d)(w, req)

	assertRedirectError(t, w, "token exchange failed")
}

func TestGitHubOAuthCallback_FetchUserFails_RedirectsWithError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.String(), "access_token"):
			return jsonResp(200, `{"access_token":"tok-1"}`), nil
		case strings.Contains(r.URL.String(), "api.github.com/user") && !strings.Contains(r.URL.String(), "emails"):
			return jsonResp(500, `{}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))

	d := Deps{Cfg: githubTestCfg()}
	req := githubCallbackReq("state=match&code=abc123", "match")
	w := httptest.NewRecorder()

	GitHubOAuthCallback(d)(w, req)

	assertRedirectError(t, w, "failed to fetch GitHub user")
}

func TestGitHubOAuthCallback_NoVerifiedPrimaryEmail_RedirectsWithError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.String(), "access_token"):
			return jsonResp(200, `{"access_token":"tok-1"}`), nil
		case strings.Contains(r.URL.String(), "/user/emails"):
			// Primary but NOT verified — must be rejected, not treated as usable.
			return jsonResp(200, `[{"email":"unverified@example.com","primary":true,"verified":false}]`), nil
		case strings.Contains(r.URL.String(), "/user"):
			return jsonResp(200, `{"id":42,"login":"octocat"}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))

	d := Deps{Cfg: githubTestCfg()}
	req := githubCallbackReq("state=match&code=abc123", "match")
	w := httptest.NewRecorder()

	GitHubOAuthCallback(d)(w, req)

	assertRedirectError(t, w, "no verified email on GitHub account")
}

func TestGitHubOAuthCallback_FullSuccess_NewUser_IssuesToken(t *testing.T) {
	pool := NewTestDBPool(t)
	username := "gh_" + RandomSuffix()
	CleanupUserByUsername(t, pool, username)

	ghID := int64(900000000) // arbitrary, unlikely to collide
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.String(), "access_token"):
			return jsonResp(200, `{"access_token":"tok-1"}`), nil
		case strings.Contains(r.URL.String(), "/user/emails"):
			return jsonResp(200, `[{"email":"`+username+`@example.com","primary":true,"verified":true}]`), nil
		case strings.Contains(r.URL.String(), "/user"):
			return jsonResp(200, `{"id":`+toJSONNum(ghID)+`,"login":"`+username+`","name":"GH User"}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))

	d := Deps{Cfg: githubTestCfg(), Pool: pool}
	req := githubCallbackReq("state=match&code=abc123", "match")
	w := httptest.NewRecorder()

	GitHubOAuthCallback(d)(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d — body: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "error=") {
		t.Fatalf("expected success redirect, got error redirect: %s", loc)
	}
	if !strings.Contains(loc, "token=") {
		t.Fatalf("expected token in redirect, got: %s", loc)
	}

	// Verify the user row was actually created with the GitHub link.
	var role, provider string
	var githubID int64
	err := pool.QueryRow(context.Background(),
		`SELECT role, oauth_provider, github_id FROM users WHERE username=$1`, username,
	).Scan(&role, &provider, &githubID)
	if err != nil {
		t.Fatalf("expected user row to exist: %v", err)
	}
	if role != "author" {
		t.Errorf("expected default role 'author', got %q", role)
	}
	if provider != "github" {
		t.Errorf("expected oauth_provider 'github', got %q", provider)
	}
	if githubID != ghID {
		t.Errorf("expected github_id %d, got %d", ghID, githubID)
	}
}

func TestGitHubOAuthCallback_LinksExistingEmailAccount(t *testing.T) {
	// Security-relevant: an account that registered natively with an email
	// must be linked (not duplicated or hijacked incorrectly) when a GitHub
	// login reports the SAME GitHub-verified primary email.
	pool := NewTestDBPool(t)
	username := "linkgh_" + RandomSuffix()
	email := username + "@example.com"
	CleanupUserByUsername(t, pool, username)

	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, email, email_verified, role) VALUES ($1,$1,$2,true,'author')`,
		username, email,
	)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	ghID := int64(900000001)
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.String(), "access_token"):
			return jsonResp(200, `{"access_token":"tok-1"}`), nil
		case strings.Contains(r.URL.String(), "/user/emails"):
			return jsonResp(200, `[{"email":"`+email+`","primary":true,"verified":true}]`), nil
		case strings.Contains(r.URL.String(), "/user"):
			return jsonResp(200, `{"id":`+toJSONNum(ghID)+`,"login":"someone-else"}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))

	d := Deps{Cfg: githubTestCfg(), Pool: pool}
	req := githubCallbackReq("state=match&code=abc123", "match")
	w := httptest.NewRecorder()

	GitHubOAuthCallback(d)(w, req)

	if w.Code != http.StatusFound || strings.Contains(w.Header().Get("Location"), "error=") {
		t.Fatalf("expected success redirect, got %d %s", w.Code, w.Header().Get("Location"))
	}

	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE email=$1`, email).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 user row for linked email, got %d (account should be linked, not duplicated)", count)
	}

	var githubID int64
	if err := pool.QueryRow(context.Background(), `SELECT github_id FROM users WHERE username=$1`, username).Scan(&githubID); err != nil {
		t.Fatalf("expected github_id linked on existing account: %v", err)
	}
	if githubID != ghID {
		t.Errorf("expected github_id %d linked, got %d", ghID, githubID)
	}
}

// toJSONNum renders an int64 for inline JSON test fixtures.
func toJSONNum(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

// ---------------------------------------------------------------------------
// Pure/unexported helper functions
// ---------------------------------------------------------------------------

func TestGithubExchangeCode_EmptyAccessToken_ReturnsError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `{}`), nil
	}))
	_, err := githubExchangeCode(context.Background(), "id", "secret", "code", "redir")
	if err == nil {
		t.Fatal("expected error for empty access_token")
	}
}

func TestGithubExchangeCode_ErrorField_ReturnsError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `{"error":"incorrect_client_credentials"}`), nil
	}))
	_, err := githubExchangeCode(context.Background(), "id", "secret", "code", "redir")
	if err == nil || !strings.Contains(err.Error(), "incorrect_client_credentials") {
		t.Fatalf("expected github error surfaced, got %v", err)
	}
}

func TestGithubFetchUser_NonOKStatus_ReturnsError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(401, `{}`), nil
	}))
	_, err := githubFetchUser(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestGithubFetchPrimaryEmail_PicksPrimaryVerifiedOnly(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `[
			{"email":"secondary@example.com","primary":false,"verified":true},
			{"email":"unverified-primary@example.com","primary":true,"verified":false},
			{"email":"the-right-one@example.com","primary":true,"verified":true}
		]`), nil
	}))
	got, err := githubFetchPrimaryEmail(context.Background(), "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "the-right-one@example.com" {
		t.Errorf("expected the primary+verified email, got %q", got)
	}
}

func TestGithubFetchPrimaryEmail_NonOKStatus_ReturnsError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(403, `{}`), nil
	}))
	_, err := githubFetchPrimaryEmail(context.Background(), "tok")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestFindOrCreateGitHubUser_DBUnreachable_ReturnsError(t *testing.T) {
	d := newDepsWithBadDB(t)
	_, err := findOrCreateGitHubUser(context.Background(), d, &githubUser{ID: 1, Login: "x"}, "x@example.com")
	if err == nil {
		t.Fatal("expected error when DB is unreachable")
	}
}

func TestEnsureUniqueUsername_DBUnreachable_ReturnsBaseUnchanged(t *testing.T) {
	d := newDepsWithBadDB(t)
	got := ensureUniqueUsername(context.Background(), d, "somebase")
	if got != "somebase" {
		t.Errorf("expected base username returned as-is when existence check fails, got %q", got)
	}
}

func TestFindOrCreateGitHubUser_ReturningUser_ExistingGitHubIDMatch(t *testing.T) {
	// The ordinary "log in again" path: github_id already links to an
	// account, so the handler must short-circuit straight to issuing a JWT
	// without touching the email-match or account-creation branches.
	pool := NewTestDBPool(t)
	username := "returngh_" + RandomSuffix()
	CleanupUserByUsername(t, pool, username)

	ghID := int64(900000002)
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, github_id, oauth_provider) VALUES ($1,$1,'moderator',$2,'github')`,
		username, ghID)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	d := Deps{Pool: pool, Cfg: &config.Config{JWTSecret: "s", JWTIssuer: "i", TokenTTL: 3_600_000_000_000}}
	tok, err := findOrCreateGitHubUser(context.Background(), d, &githubUser{ID: ghID, Login: "irrelevant"}, "irrelevant@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok == "" {
		t.Fatal("expected token")
	}

	// The role returned must be the EXISTING account's role (moderator), not
	// a fresh 'author' default — otherwise repeat logins would silently
	// downgrade/upgrade privileges.
	claims, err := auth.Verify(tok, "s")
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.Sub != username {
		t.Errorf("expected sub=%q, got %q", username, claims.Sub)
	}
	if claims.Role != "moderator" {
		t.Errorf("expected the existing account's role 'moderator' preserved, got %q", claims.Role)
	}
}

func TestEnsureUniqueUsername_RealDB_AppendsSuffixOnCollision(t *testing.T) {
	pool := NewTestDBPool(t)
	base := "collide_" + RandomSuffix()
	CleanupUserByUsername(t, pool, base)
	CleanupUserByUsername(t, pool, base+"_2")

	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role) VALUES ($1,$1,'author')`, base)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	d := Deps{Pool: pool}
	got := ensureUniqueUsername(context.Background(), d, base)
	if got != base+"_2" {
		t.Errorf("expected suffix _2 on collision, got %q", got)
	}
}
