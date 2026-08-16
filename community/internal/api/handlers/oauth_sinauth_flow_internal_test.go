package handlers

// HTTP-level and helper-function tests for the sinauth SSO OAuth flow
// (oauth_sinauth.go) — the ecosystem's own identity-provider integration.
// No tests existed for this file before this pass, unlike GitHub/Google.
//
// Security focus:
//   - CSRF state validation (same pattern as GitHub/Google).
//   - PKCE: the code_verifier must actually be sent in the token exchange
//     request, and a missing PKCE cookie must hard-fail the callback. PKCE
//     is what stops an attacker who intercepts the authorization code (e.g.
//     via a leaky redirect/referrer) from completing the exchange without
//     also having the original browser session's verifier.
//   - Unlike GitHub/Google, sinauth's "ID" is verified by us calling
//     sinauth's own /oauth/userinfo endpoint with the access token we
//     obtained directly from sinauth's token endpoint — so there's no
//     client-supplied token to validate the issuer/audience of (the trust
//     boundary is "we contacted sinauthURL ourselves"). This is fine AS LONG
//     AS d.Cfg.SinauthURL is trustworthy server config, which it is.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func sinauthTestCfg() *config.Config {
	return &config.Config{
		SinauthURL:          "https://sinauth.internal.test",
		SinauthPublicURL:    "https://sinauth.public.test",
		SinauthClientID:     "sinauth-client-id",
		SinauthClientSecret: "sinauth-client-secret",
		SinauthCallbackURL:  "https://example.test/api/v1/auth/sinauth/callback",
		SiteURL:             "https://frontend.test",
		JWTSecret:           "unit-test-secret-unit-test-secret",
		JWTIssuer:           "test",
		TokenTTL:            3_600_000_000_000,
	}
}

func sinauthCallbackReq(query, stateCookie, pkceCookie string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sinauth/callback?"+query, nil)
	if stateCookie != "" {
		req.AddCookie(&http.Cookie{Name: "sinauth_oauth_state", Value: stateCookie})
	}
	if pkceCookie != "" {
		req.AddCookie(&http.Cookie{Name: "sinauth_pkce", Value: pkceCookie})
	}
	return req
}

// ---------------------------------------------------------------------------
// SinauthOAuthStart
// ---------------------------------------------------------------------------

func TestSinauthOAuthStart_SetsStateAndPKCECookies(t *testing.T) {
	d := Deps{Cfg: sinauthTestCfg()}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sinauth", nil)
	w := httptest.NewRecorder()

	SinauthOAuthStart(d)(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	var stateCookie, pkceCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "sinauth_oauth_state":
			stateCookie = c
		case "sinauth_pkce":
			pkceCookie = c
		}
	}
	if stateCookie == nil || stateCookie.Value == "" {
		t.Fatal("expected non-empty sinauth_oauth_state cookie")
	}
	if pkceCookie == nil || pkceCookie.Value == "" {
		t.Fatal("expected non-empty sinauth_pkce cookie (code_verifier)")
	}
	if !stateCookie.HttpOnly || !pkceCookie.HttpOnly {
		t.Error("both state and PKCE cookies must be HttpOnly")
	}

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("bad Location: %v", err)
	}
	if loc.Query().Get("state") != stateCookie.Value {
		t.Error("redirect state must match the state cookie")
	}
	if loc.Query().Get("code_challenge_method") != "S256" {
		t.Errorf("expected S256 PKCE method, got %q", loc.Query().Get("code_challenge_method"))
	}
	challenge := loc.Query().Get("code_challenge")
	if challenge == "" {
		t.Fatal("expected non-empty code_challenge")
	}
	if challenge == pkceCookie.Value {
		t.Error("code_challenge must be the S256 hash of code_verifier, not the verifier itself")
	}

	// Must use the browser-facing public URL, not the internal one.
	if !strings.HasPrefix(loc.String(), "https://sinauth.public.test") {
		t.Errorf("expected authorize redirect to use SinauthPublicURL, got %s", loc.String())
	}
}

func TestSinauthOAuthStart_FallsBackToSinauthURL_WhenPublicURLUnset(t *testing.T) {
	cfg := sinauthTestCfg()
	cfg.SinauthPublicURL = ""
	d := Deps{Cfg: cfg}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sinauth", nil)
	w := httptest.NewRecorder()

	SinauthOAuthStart(d)(w, req)

	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, cfg.SinauthURL) {
		t.Errorf("expected fallback to SinauthURL, got %s", loc)
	}
}

// ---------------------------------------------------------------------------
// SinauthOAuthCallback — CSRF / PKCE / validation branches (no network)
// ---------------------------------------------------------------------------

func TestSinauthOAuthCallback_MissingStateCookie_RedirectsWithError(t *testing.T) {
	d := Deps{Cfg: sinauthTestCfg()}
	w := httptest.NewRecorder()
	SinauthOAuthCallback(d)(w, sinauthCallbackReq("state=x&code=y", "", ""))
	assertRedirectError(t, w, "missing state")
}

func TestSinauthOAuthCallback_StateMismatch_RedirectsWithError(t *testing.T) {
	d := Deps{Cfg: sinauthTestCfg()}
	w := httptest.NewRecorder()
	SinauthOAuthCallback(d)(w, sinauthCallbackReq("state=attacker&code=y", "real", "verifier"))
	assertRedirectError(t, w, "state mismatch")
}

func TestSinauthOAuthCallback_StateMismatch_ClearsBothCookies(t *testing.T) {
	d := Deps{Cfg: sinauthTestCfg()}
	w := httptest.NewRecorder()
	SinauthOAuthCallback(d)(w, sinauthCallbackReq("state=attacker&code=y", "real", "verifier"))

	seen := map[string]bool{}
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			seen[c.Name] = true
		}
	}
	if !seen["sinauth_oauth_state"] {
		t.Error("expected sinauth_oauth_state to be cleared on mismatch")
	}
}

// SECURITY: a missing PKCE verifier must hard-fail the callback — without
// it, the code exchange either fails at sinauth (good) or, if sinauth ever
// tolerated a missing verifier, would let anyone with just the authorization
// code (not the original browser's verifier) complete login.
func TestSinauthOAuthCallback_MissingPKCECookie_RedirectsWithError(t *testing.T) {
	d := Deps{Cfg: sinauthTestCfg()}
	w := httptest.NewRecorder()
	SinauthOAuthCallback(d)(w, sinauthCallbackReq("state=match&code=abc", "match", ""))
	assertRedirectError(t, w, "missing pkce")
}

func TestSinauthOAuthCallback_MissingCode_RedirectsWithError(t *testing.T) {
	d := Deps{Cfg: sinauthTestCfg()}
	w := httptest.NewRecorder()
	SinauthOAuthCallback(d)(w, sinauthCallbackReq("state=match", "match", "verifier"))
	assertRedirectError(t, w, "no code returned by sinauth")
}

// ---------------------------------------------------------------------------
// SinauthOAuthCallback — network-dependent branches (stubbed transport)
// ---------------------------------------------------------------------------

func TestSinauthOAuthCallback_TokenExchangeFails_RedirectsWithError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.String(), "/oauth/token") {
			return jsonResp(400, `{"error":"invalid_grant"}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))
	d := Deps{Cfg: sinauthTestCfg()}
	w := httptest.NewRecorder()
	SinauthOAuthCallback(d)(w, sinauthCallbackReq("state=match&code=abc", "match", "verifier"))
	assertRedirectError(t, w, "token exchange failed")
}

func TestSinauthOAuthCallback_UserInfoFails_RedirectsWithError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.String(), "/oauth/token"):
			return jsonResp(200, `{"access_token":"tok-1"}`), nil
		case strings.Contains(r.URL.String(), "/oauth/userinfo"):
			return jsonResp(401, `{}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))
	d := Deps{Cfg: sinauthTestCfg()}
	w := httptest.NewRecorder()
	SinauthOAuthCallback(d)(w, sinauthCallbackReq("state=match&code=abc", "match", "verifier"))
	assertRedirectError(t, w, "failed to fetch sinauth user info")
}

func TestSinauthOAuthCallback_UserInfoMissingSub_RedirectsWithError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.String(), "/oauth/token"):
			return jsonResp(200, `{"access_token":"tok-1"}`), nil
		case strings.Contains(r.URL.String(), "/oauth/userinfo"):
			return jsonResp(200, `{"email":"noSub@example.com"}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))
	d := Deps{Cfg: sinauthTestCfg()}
	w := httptest.NewRecorder()
	SinauthOAuthCallback(d)(w, sinauthCallbackReq("state=match&code=abc", "match", "verifier"))
	assertRedirectError(t, w, "failed to fetch sinauth user info")
}

func TestSinauthOAuthCallback_FullSuccess_NewUser_IssuesToken(t *testing.T) {
	pool := NewTestDBPool(t)
	sub := "sinauth-sub-" + RandomSuffix()
	var capturedVerifier string

	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.String(), "/oauth/token"):
			body := r.Body
			buf := make([]byte, 4096)
			n, _ := body.Read(buf)
			form, _ := url.ParseQuery(string(buf[:n]))
			capturedVerifier = form.Get("code_verifier")
			return jsonResp(200, `{"access_token":"tok-1"}`), nil
		case strings.Contains(r.URL.String(), "/oauth/userinfo"):
			return jsonResp(200, `{"sub":"`+sub+`","email":"`+sub+`@example.com","name":"Sinauth User"}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))

	d := Deps{Cfg: sinauthTestCfg(), Pool: pool}
	w := httptest.NewRecorder()
	SinauthOAuthCallback(d)(w, sinauthCallbackReq("state=match&code=abc", "match", "the-real-verifier"))

	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || strings.Contains(loc, "error=") {
		t.Fatalf("expected success redirect, got %d %s", w.Code, loc)
	}
	if !strings.Contains(loc, "token=") {
		t.Fatalf("expected token in redirect, got %s", loc)
	}
	if capturedVerifier != "the-real-verifier" {
		t.Errorf("expected code_verifier %q to be sent in the token exchange, got %q", "the-real-verifier", capturedVerifier)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE sinauth_id=$1`, sub)
	})

	var provider string
	if err := pool.QueryRow(context.Background(), `SELECT oauth_provider FROM users WHERE sinauth_id=$1`, sub).Scan(&provider); err != nil {
		t.Fatalf("expected created user row: %v", err)
	}
	if provider != "sinauth" {
		t.Errorf("expected oauth_provider=sinauth, got %q", provider)
	}
}

// ---------------------------------------------------------------------------
// sinauthExchangeCode — PKCE wiring
// ---------------------------------------------------------------------------

func TestSinauthExchangeCode_SendsCodeVerifier(t *testing.T) {
	var gotForm url.Values
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotForm, _ = url.ParseQuery(string(buf[:n]))
		return jsonResp(200, `{"access_token":"tok"}`), nil
	}))
	_, err := sinauthExchangeCode(context.Background(), "https://sinauth.test", "client-id", "secret", "https://cb", "code123", "verifier456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotForm.Get("code_verifier") != "verifier456" {
		t.Errorf("expected code_verifier=verifier456 in token request, got %q", gotForm.Get("code_verifier"))
	}
	if gotForm.Get("grant_type") != "authorization_code" {
		t.Errorf("expected grant_type=authorization_code, got %q", gotForm.Get("grant_type"))
	}
}

func TestSinauthExchangeCode_OmitsClientSecretWhenEmpty(t *testing.T) {
	var gotForm url.Values
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		gotForm, _ = url.ParseQuery(string(buf[:n]))
		return jsonResp(200, `{"access_token":"tok"}`), nil
	}))
	_, err := sinauthExchangeCode(context.Background(), "https://sinauth.test", "client-id", "", "https://cb", "code123", "verifier456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotForm.Has("client_secret") {
		t.Error("expected client_secret to be omitted from the form when empty (public client / PKCE-only)")
	}
}

func TestSinauthExchangeCode_ErrorField_ReturnsError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(400, `{"error":"invalid_grant"}`), nil
	}))
	_, err := sinauthExchangeCode(context.Background(), "https://sinauth.test", "id", "secret", "https://cb", "code", "verifier")
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("expected sinauth error surfaced, got %v", err)
	}
}

func TestSinauthExchangeCode_EmptyAccessToken_ReturnsError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `{}`), nil
	}))
	_, err := sinauthExchangeCode(context.Background(), "https://sinauth.test", "id", "secret", "https://cb", "code", "verifier")
	if err == nil {
		t.Fatal("expected error for empty access_token")
	}
}

// ---------------------------------------------------------------------------
// sinauthFetchUserInfo
// ---------------------------------------------------------------------------

func TestSinauthFetchUserInfo_NonOKStatus_ReturnsError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(403, `{}`), nil
	}))
	_, err := sinauthFetchUserInfo(context.Background(), "https://sinauth.test", "tok")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestSinauthFetchUserInfo_SendsBearerToken(t *testing.T) {
	var gotAuth string
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		return jsonResp(200, `{"sub":"s","email":"e@example.com"}`), nil
	}))
	_, err := sinauthFetchUserInfo(context.Background(), "https://sinauth.test", "the-access-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer the-access-token" {
		t.Errorf("expected Bearer auth header, got %q", gotAuth)
	}
}

// ---------------------------------------------------------------------------
// findOrCreateSinauthUser — DB-backed
// ---------------------------------------------------------------------------

func TestFindOrCreateSinauthUser_DBUnreachable_ReturnsError(t *testing.T) {
	d := newDepsWithBadDB(t)
	_, err := findOrCreateSinauthUser(context.Background(), d, &sinauthUserInfo{Sub: "s", Email: "e@example.com"})
	if err == nil {
		t.Fatal("expected error when DB is unreachable")
	}
}

func TestFindOrCreateSinauthUser_ReturningUser_ExistingSinauthIDMatch(t *testing.T) {
	pool := NewTestDBPool(t)
	username := "returnsin_" + RandomSuffix()
	CleanupUserByUsername(t, pool, username)

	sub := "sinauth-returning-" + RandomSuffix()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, sinauth_id, oauth_provider) VALUES ($1,$1,'moderator',$2,'sinauth')`,
		username, sub)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	d := Deps{Pool: pool, Cfg: &config.Config{JWTSecret: "s", JWTIssuer: "i", TokenTTL: 3_600_000_000_000}}
	tok, err := findOrCreateSinauthUser(context.Background(), d, &sinauthUserInfo{Sub: sub, Email: "irrelevant@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	claims, err := auth.Verify(tok, "s")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Role != "moderator" {
		t.Errorf("expected existing role preserved, got %q", claims.Role)
	}
}

func TestFindOrCreateSinauthUser_LinksExistingEmailAccount(t *testing.T) {
	pool := NewTestDBPool(t)
	username := "linksin_" + RandomSuffix()
	email := username + "@example.com"
	CleanupUserByUsername(t, pool, username)

	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, email, email_verified, role) VALUES ($1,$1,$2,true,'author')`,
		username, email,
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	sub := "sinauth-sub-" + RandomSuffix()
	tok, err := findOrCreateSinauthUser(context.Background(),
		Deps{Pool: pool, Cfg: &config.Config{JWTSecret: "s", JWTIssuer: "i", TokenTTL: 3_600_000_000_000}},
		&sinauthUserInfo{Sub: sub, Email: email, Name: "Someone"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}

	var sinauthID string
	if err := pool.QueryRow(context.Background(), `SELECT sinauth_id FROM users WHERE username=$1`, username).Scan(&sinauthID); err != nil {
		t.Fatalf("expected sinauth_id linked: %v", err)
	}
	if sinauthID != sub {
		t.Errorf("expected linked sinauth_id %q, got %q", sub, sinauthID)
	}

	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE email=$1`, email).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row for linked email, got %d", count)
	}
}

func TestFindOrCreateSinauthUser_NewUser_DerivesUsernameFromSubLocalPart(t *testing.T) {
	pool := NewTestDBPool(t)
	sub := "newsinuser_" + RandomSuffix() + "@idp.example"

	tok, err := findOrCreateSinauthUser(context.Background(),
		Deps{Pool: pool, Cfg: &config.Config{JWTSecret: "s", JWTIssuer: "i", TokenTTL: 3_600_000_000_000}},
		&sinauthUserInfo{Sub: sub, Email: "", Name: ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}

	wantUsername := strings.SplitN(sub, "@", 2)[0]
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE username=$1`, wantUsername) })

	var role string
	if err := pool.QueryRow(context.Background(), `SELECT role FROM users WHERE username=$1`, wantUsername).Scan(&role); err != nil {
		t.Fatalf("expected user created with derived username %q: %v", wantUsername, err)
	}
}
