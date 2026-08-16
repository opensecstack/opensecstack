package handlers

// HTTP-level and helper-function tests for the Google OAuth flow
// (oauth_google.go). Security focus: CSRF state validation and — the most
// important check in this file — that parseGoogleIDToken rejects a token
// whose audience (aud) does not match our own client_id. Skipping that check
// is the textbook "OAuth token substitution" bug: a token minted for a
// DIFFERENT Google OAuth client (e.g. an attacker's own app) would otherwise
// be accepted as proof of identity for this app.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

func googleTestCfg() *config.Config {
	return &config.Config{
		GoogleClientID:     "google-client-id",
		GoogleClientSecret: "google-client-secret",
		GoogleRedirectURI:  "https://example.test/api/v1/auth/google/callback",
		SiteURL:            "https://frontend.test",
		JWTSecret:          "unit-test-secret-unit-test-secret",
		JWTIssuer:          "test",
		TokenTTL:           3_600_000_000_000,
	}
}

func googleCallbackReq(query string, stateCookie string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google/callback?"+query, nil)
	if stateCookie != "" {
		req.AddCookie(&http.Cookie{Name: "google_oauth_state", Value: stateCookie})
	}
	return req
}

// ---------------------------------------------------------------------------
// GoogleOAuthStart
// ---------------------------------------------------------------------------

func TestGoogleOAuthStart_SetsStateCookieAndRedirectsWithExpectedParams(t *testing.T) {
	d := Deps{Cfg: googleTestCfg()}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/google", nil)
	w := httptest.NewRecorder()

	GoogleOAuthStart(d)(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	var stateCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "google_oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil || stateCookie.Value == "" {
		t.Fatal("expected non-empty google_oauth_state cookie")
	}
	if !stateCookie.HttpOnly || stateCookie.SameSite != http.SameSiteLaxMode {
		t.Error("expected HttpOnly, SameSite=Lax state cookie")
	}

	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "response_type=code") {
		t.Errorf("expected response_type=code in redirect, got %s", loc)
	}
	if !strings.Contains(loc, "state="+stateCookie.Value) {
		t.Errorf("expected redirect state to match cookie state, got %s", loc)
	}
	if !strings.Contains(loc, "scope=openid") {
		t.Errorf("expected openid scope in redirect, got %s", loc)
	}
}

// ---------------------------------------------------------------------------
// GoogleOAuthCallback — CSRF / validation branches (no network)
// ---------------------------------------------------------------------------

func TestGoogleOAuthCallback_MissingStateCookie_RedirectsWithError(t *testing.T) {
	d := Deps{Cfg: googleTestCfg()}
	w := httptest.NewRecorder()
	GoogleOAuthCallback(d)(w, googleCallbackReq("state=x&code=y", ""))
	assertRedirectError(t, w, "missing state")
}

func TestGoogleOAuthCallback_StateMismatch_RedirectsWithError(t *testing.T) {
	d := Deps{Cfg: googleTestCfg()}
	w := httptest.NewRecorder()
	GoogleOAuthCallback(d)(w, googleCallbackReq("state=attacker&code=y", "real"))
	assertRedirectError(t, w, "state mismatch")
}

func TestGoogleOAuthCallback_StateMismatch_ClearsCookie(t *testing.T) {
	d := Deps{Cfg: googleTestCfg()}
	w := httptest.NewRecorder()
	GoogleOAuthCallback(d)(w, googleCallbackReq("state=attacker&code=y", "real"))

	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "google_oauth_state" {
			found = true
			if c.MaxAge >= 0 {
				t.Errorf("expected expired cookie, got MaxAge=%d", c.MaxAge)
			}
		}
	}
	if !found {
		t.Error("expected state cookie to be cleared on mismatch")
	}
}

func TestGoogleOAuthCallback_MissingCode_RedirectsWithError(t *testing.T) {
	d := Deps{Cfg: googleTestCfg()}
	w := httptest.NewRecorder()
	GoogleOAuthCallback(d)(w, googleCallbackReq("state=match", "match"))
	assertRedirectError(t, w, "no code returned by Google")
}

// ---------------------------------------------------------------------------
// GoogleOAuthCallback — network-dependent branches (stubbed transport)
// ---------------------------------------------------------------------------

func TestGoogleOAuthCallback_TokenExchangeFails_RedirectsWithError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.String(), "oauth2.googleapis.com/token") {
			return jsonResp(400, `{"error":"invalid_grant"}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))
	d := Deps{Cfg: googleTestCfg()}
	w := httptest.NewRecorder()
	GoogleOAuthCallback(d)(w, googleCallbackReq("state=match&code=abc", "match"))
	assertRedirectError(t, w, "token exchange failed")
}

func TestGoogleOAuthCallback_TokenInfoRejectsToken_RedirectsWithError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.String(), "tokeninfo"):
			return jsonResp(400, `{"error_description":"Invalid Value"}`), nil
		case strings.Contains(r.URL.String(), "oauth2.googleapis.com/token"):
			return jsonResp(200, `{"id_token":"header.payload.sig"}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))
	d := Deps{Cfg: googleTestCfg()}
	w := httptest.NewRecorder()
	GoogleOAuthCallback(d)(w, googleCallbackReq("state=match&code=abc", "match"))
	assertRedirectError(t, w, "failed to parse Google ID token")
}

func TestGoogleOAuthCallback_FullSuccess_NewUser_IssuesToken(t *testing.T) {
	pool := NewTestDBPool(t)
	username := "goog_" + RandomSuffix()
	email := username + "@example.com"
	CleanupUserByUsername(t, pool, username)

	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(r.URL.String(), "tokeninfo"):
			return jsonResp(200, `{"sub":"google-sub-`+username+`","email":"`+email+`","name":"Google User","aud":"google-client-id"}`), nil
		case strings.Contains(r.URL.String(), "oauth2.googleapis.com/token"):
			return jsonResp(200, `{"id_token":"header.payload.sig"}`), nil
		}
		t.Fatalf("unexpected request to %s", r.URL)
		return nil, nil
	}))

	d := Deps{Cfg: googleTestCfg(), Pool: pool}
	w := httptest.NewRecorder()
	GoogleOAuthCallback(d)(w, googleCallbackReq("state=match&code=abc", "match"))

	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || strings.Contains(loc, "error=") {
		t.Fatalf("expected success redirect, got %d %s", w.Code, loc)
	}
	if !strings.Contains(loc, "token=") {
		t.Fatalf("expected token param, got %s", loc)
	}

	var googleID string
	if err := pool.QueryRow(context.Background(), `SELECT google_id FROM users WHERE username=$1`, username).Scan(&googleID); err != nil {
		t.Fatalf("expected created user row: %v", err)
	}
	if googleID != "google-sub-"+username {
		t.Errorf("expected google_id linked, got %q", googleID)
	}
}

// ---------------------------------------------------------------------------
// parseGoogleIDToken — the security-critical audience check
// ---------------------------------------------------------------------------

func TestParseGoogleIDToken_AudienceMismatch_Rejected(t *testing.T) {
	// This is THE critical check: a valid, well-formed, Google-signed token
	// minted for a DIFFERENT OAuth client must never be accepted here — that
	// is exactly the token-substitution attack this check exists to stop.
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `{"sub":"victim-sub","email":"victim@example.com","aud":"some-other-app-client-id"}`), nil
	}))
	_, err := parseGoogleIDToken(context.Background(), "our-client-id", "tok")
	if err == nil {
		t.Fatal("expected audience mismatch to be rejected")
	}
	if !strings.Contains(err.Error(), "audience mismatch") {
		t.Errorf("expected audience mismatch error, got %v", err)
	}
}

func TestParseGoogleIDToken_AudienceMatch_Accepted(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `{"sub":"user-sub","email":"user@example.com","name":"User","aud":"our-client-id"}`), nil
	}))
	claims, err := parseGoogleIDToken(context.Background(), "our-client-id", "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Sub != "user-sub" || claims.Email != "user@example.com" {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

func TestParseGoogleIDToken_NonOKStatus_Rejected(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(400, `{}`), nil
	}))
	_, err := parseGoogleIDToken(context.Background(), "our-client-id", "tok")
	if err == nil {
		t.Fatal("expected non-200 tokeninfo status to be rejected")
	}
}

func TestParseGoogleIDToken_ErrorDescription_Rejected(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `{"error_description":"Invalid Value"}`), nil
	}))
	_, err := parseGoogleIDToken(context.Background(), "our-client-id", "tok")
	if err == nil {
		t.Fatal("expected error_description field to be surfaced as an error")
	}
}

func TestParseGoogleIDToken_MissingSubOrEmail_Rejected(t *testing.T) {
	cases := []string{
		`{"sub":"","email":"user@example.com","aud":"our-client-id"}`,
		`{"sub":"user-sub","email":"","aud":"our-client-id"}`,
	}
	for _, body := range cases {
		StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			return jsonResp(200, body), nil
		}))
		_, err := parseGoogleIDToken(context.Background(), "our-client-id", "tok")
		if err == nil {
			t.Errorf("expected incomplete tokeninfo response %q to be rejected", body)
		}
	}
}

// ---------------------------------------------------------------------------
// googleExchangeCode
// ---------------------------------------------------------------------------

func TestGoogleExchangeCode_EmptyIDToken_ReturnsError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `{}`), nil
	}))
	_, err := googleExchangeCode(context.Background(), "id", "secret", "redir", "code")
	if err == nil {
		t.Fatal("expected error for empty id_token")
	}
}

func TestGoogleExchangeCode_ErrorField_ReturnsError(t *testing.T) {
	StubOAuthHTTPClient(t, RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return jsonResp(200, `{"error":"invalid_grant"}`), nil
	}))
	_, err := googleExchangeCode(context.Background(), "id", "secret", "redir", "code")
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("expected google error surfaced, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// findOrCreateGoogleUser — DB-backed
// ---------------------------------------------------------------------------

func TestFindOrCreateGoogleUser_DBUnreachable_ReturnsError(t *testing.T) {
	d := newDepsWithBadDB(t)
	_, err := findOrCreateGoogleUser(context.Background(), d, &googleIDTokenClaims{Sub: "s", Email: "e@example.com"})
	if err == nil {
		t.Fatal("expected error when DB is unreachable")
	}
}

func TestFindOrCreateGoogleUser_ReturningUser_ExistingGoogleIDMatch(t *testing.T) {
	pool := NewTestDBPool(t)
	username := "returngoog_" + RandomSuffix()
	CleanupUserByUsername(t, pool, username)

	googleID := "google-returning-" + RandomSuffix()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, role, google_id, oauth_provider) VALUES ($1,$1,'moderator',$2,'google')`,
		username, googleID)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	d := Deps{Pool: pool, Cfg: &config.Config{JWTSecret: "s", JWTIssuer: "i", TokenTTL: 3_600_000_000_000}}
	tok, err := findOrCreateGoogleUser(context.Background(), d, &googleIDTokenClaims{Sub: googleID, Email: "irrelevant@example.com"})
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

func TestFindOrCreateGoogleUser_LinksExistingEmailAccount(t *testing.T) {
	pool := NewTestDBPool(t)
	username := "linkgoogle_" + RandomSuffix()
	email := username + "@example.com"
	CleanupUserByUsername(t, pool, username)

	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (username, display_name, email, email_verified, role) VALUES ($1,$1,$2,true,'author')`,
		username, email,
	)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	tok, err := findOrCreateGoogleUser(context.Background(), Deps{Pool: pool, Cfg: &config.Config{JWTSecret: "s", JWTIssuer: "i", TokenTTL: 3_600_000_000_000}},
		&googleIDTokenClaims{Sub: "new-google-sub", Email: email, Name: "Someone"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}

	var googleID string
	if err := pool.QueryRow(context.Background(), `SELECT google_id FROM users WHERE username=$1`, username).Scan(&googleID); err != nil {
		t.Fatalf("expected google_id linked: %v", err)
	}
	if googleID != "new-google-sub" {
		t.Errorf("expected linked google_id, got %q", googleID)
	}

	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE email=$1`, email).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row for linked email, got %d", count)
	}
}
