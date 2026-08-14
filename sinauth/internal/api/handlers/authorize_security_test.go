//go:build integration

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/sinauth/internal/client"
)

// This file focuses on the security-critical guarantees of /oauth/authorize:
// redirect_uri must be allowlisted per client (open-redirect protection),
// PKCE must be enforced when a client requires it, scopes must be limited to
// what the client is allowed, and an invalid/unknown client_id must never be
// silently accepted. It complements authorize_test.go (which covers the ADR
// 005 organization-context resolution) using the same DB-backed test
// helpers (requireDB, testDeps, createTestOAuthClient, createTestAuthorizeUser).

// doAuthorizeGET issues a GET /oauth/authorize request with the given query
// values and returns the recorded response.
func doAuthorizeGET(t *testing.T, d Deps, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	AuthorizeGET(d)(rec, req)
	return rec
}

func baseAuthorizeQuery(clientID, redirectURI string) url.Values {
	return url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {"openid profile"},
		"state":         {"xyz"},
	}
}

// createPKCEClient registers a test client with RequirePKCE=true so tests can
// prove PKCE enforcement independently of the default (RequirePKCE=false)
// createTestOAuthClient helper.
func createPKCEClient(t *testing.T, d Deps, redirectURI string) string {
	t.Helper()
	clientID := fmt.Sprintf("test-pkce-client-%d", time.Now().UnixNano())
	c := &client.Client{
		ClientID:      clientID,
		Name:          "PKCE Test Client",
		RedirectURIs:  []string{redirectURI},
		AllowedScopes: []string{"openid", "profile"},
		GrantTypes:    []string{"authorization_code"},
		RequirePKCE:   true,
	}
	if err := d.ClientSvc.Create(context.Background(), c); err != nil {
		t.Fatalf("create PKCE test client: %v", err)
	}
	t.Cleanup(func() { _ = d.ClientSvc.Delete(context.Background(), clientID) })
	return clientID
}

// -------------------- AuthorizeGET --------------------

func TestAuthorizeGET_UnsupportedResponseType_Returns400(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)

	q := baseAuthorizeQuery("whatever", "https://client.test/callback")
	q.Set("response_type", "token") // implicit grant, not supported
	rec := doAuthorizeGET(t, d, q)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestAuthorizeGET_InvalidClientID_Returns400(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)

	q := baseAuthorizeQuery("does-not-exist-"+fmt.Sprint(time.Now().UnixNano()), "https://client.test/callback")
	rec := doAuthorizeGET(t, d, q)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Fatalf("body = %q, want it to mention invalid_client", rec.Body.String())
	}
}

// Open-redirect protection: a redirect_uri that isn't in the client's
// registered allowlist must be rejected outright (not redirected to), since
// redirecting an error to an attacker-controlled, unregistered URI would
// itself be exploitable.
func TestAuthorizeGET_RedirectURINotInAllowlist_Returns400(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	registeredURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, registeredURI)

	q := baseAuthorizeQuery(clientID, "https://evil.attacker.test/steal")
	rec := doAuthorizeGET(t, d, q)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "evil.attacker.test") {
		t.Fatalf("must never redirect to an unregistered redirect_uri; Location=%q", loc)
	}
}

func TestAuthorizeGET_DisallowedScope_RedirectsWithInvalidScopeError(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI) // AllowedScopes: openid, profile

	q := baseAuthorizeQuery(clientID, redirectURI)
	q.Set("scope", "openid profile admin:all")
	rec := doAuthorizeGET(t, d, q)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_scope") {
		t.Fatalf("Location = %q, expected error=invalid_scope", loc)
	}
	// The error redirect must still go back to the legitimate, registered
	// redirect_uri — not somewhere else.
	if !strings.HasPrefix(loc, redirectURI) {
		t.Fatalf("Location = %q, expected it to be rooted at the registered redirect_uri %q", loc, redirectURI)
	}
}

func TestAuthorizeGET_PKCERequired_MissingChallenge_RedirectsWithInvalidRequestError(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createPKCEClient(t, d, redirectURI)

	q := baseAuthorizeQuery(clientID, redirectURI) // no code_challenge
	rec := doAuthorizeGET(t, d, q)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("Location = %q, expected error=invalid_request when a PKCE-required client omits code_challenge", loc)
	}
}

func TestAuthorizeGET_PKCERequired_WithChallenge_ProceedsToLogin(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createPKCEClient(t, d, redirectURI)

	q := baseAuthorizeQuery(clientID, redirectURI)
	q.Set("code_challenge", "abc123challenge")
	q.Set("code_challenge_method", "S256")
	rec := doAuthorizeGET(t, d, q)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/oauth/login") {
		t.Fatalf("Location = %q, expected redirect to /oauth/login", loc)
	}
}

func TestAuthorizeGET_HappyPath_RedirectsToLoginPreservingAllParams(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)

	q := baseAuthorizeQuery(clientID, redirectURI)
	q.Set("organization_id", "org-123")
	q.Set("nonce", "n-abc")
	rec := doAuthorizeGET(t, d, q)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if !strings.HasPrefix(loc, d.Cfg.SiteURL+"/oauth/login?") {
		t.Fatalf("Location = %q, expected it rooted at SiteURL/oauth/login", loc)
	}
	qp := parsed.Query()
	for k, want := range map[string]string{
		"client_id":       clientID,
		"redirect_uri":    redirectURI,
		"organization_id": "org-123",
		"nonce":           "n-abc",
		"state":           "xyz",
	} {
		if got := qp.Get(k); got != want {
			t.Errorf("query[%s] = %q, want %q (Location=%q)", k, got, want, loc)
		}
	}
}

// -------------------- AuthorizePOST security re-validation --------------------
//
// AuthorizePOST is reachable directly (it is a standalone stateless HTTP
// endpoint; nothing binds a POST to a prior AuthorizeGET call), so it must
// perform the exact same client/redirect_uri/scope/PKCE validation as
// AuthorizeGET before it authenticates the user or issues a code. These
// tests are regression tests for that guarantee.

// Open-redirect / code-exfiltration guard: an unregistered redirect_uri must
// never receive an issued authorization code, even if the submitted
// username/password are valid.
func TestAuthorizePOST_RedirectURINotInAllowlist_Rejected(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	registeredURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, registeredURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("openredir-%d", time.Now().UnixNano()))

	form := baseForm(u.Username, clientID, "https://evil.attacker.test/collect")
	rec := doAuthorizePOST(t, d, form)

	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "evil.attacker.test") {
		t.Fatalf("authorization code must never be delivered to an unregistered redirect_uri; Location=%q", loc)
	}
	if strings.Contains(rec.Body.String()+loc, "code=") {
		t.Fatalf("no authorization code should be issued for an unregistered redirect_uri; body=%s Location=%s", rec.Body.String(), loc)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (invalid_redirect_uri rejected before authentication); body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// An unknown/unregistered client_id must be rejected, not silently accepted
// (issueAuthCode's client_id foreign key would eventually fail, but the
// handler must reject this before ever touching credentials or the DB).
func TestAuthorizePOST_InvalidClientID_Rejected(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("badclient-%d", time.Now().UnixNano()))

	form := baseForm(u.Username, "no-such-client-"+fmt.Sprint(time.Now().UnixNano()), "https://client.test/callback")
	rec := doAuthorizePOST(t, d, form)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Fatalf("body = %q, want it to mention invalid_client", rec.Body.String())
	}
}

// A client may not be granted scopes outside its AllowedScopes, even by a
// direct POST that never went through AuthorizeGET's scope check.
func TestAuthorizePOST_DisallowedScope_NoCodeIssued(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI) // AllowedScopes: openid, profile
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("badscope-%d", time.Now().UnixNano()))

	form := baseForm(u.Username, clientID, redirectURI)
	form.Set("scope", "openid profile admin:all")
	rec := doAuthorizePOST(t, d, form)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_scope") {
		t.Fatalf("Location = %q, expected error=invalid_scope", loc)
	}
	if strings.Contains(loc, "code=") {
		t.Fatalf("Location = %q, no code should be issued for a disallowed scope request", loc)
	}
}

// A client with require_pkce=true must not be able to have that requirement
// bypassed by simply omitting code_challenge from the POST body (the
// AuthorizeGET-only check would have let this through before the fix).
func TestAuthorizePOST_PKCERequired_MissingChallenge_NoCodeIssued(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createPKCEClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("pkcebypass-%d", time.Now().UnixNano()))

	form := baseForm(u.Username, clientID, redirectURI) // no code_challenge
	rec := doAuthorizePOST(t, d, form)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Fatalf("Location = %q, expected error=invalid_request (PKCE required but no code_challenge)", loc)
	}
	if strings.Contains(loc, "code=") {
		t.Fatalf("Location = %q, no code should be issued when a PKCE-required client omits code_challenge", loc)
	}
}

// With a valid code_challenge present, a PKCE-required client proceeds
// normally and a code is issued (the challenge itself is verified later, at
// the /oauth/token exchange).
func TestAuthorizePOST_PKCERequired_WithChallenge_IssuesCode(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createPKCEClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("pkceok-%d", time.Now().UnixNano()))

	form := baseForm(u.Username, clientID, redirectURI)
	form.Set("code_challenge", "abc123challenge")
	form.Set("code_challenge_method", "S256")
	rec := doAuthorizePOST(t, d, form)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "code=") {
		t.Fatalf("Location = %q, expected a code param", loc)
	}
}

// A wrong password must be rejected and must never issue a code, regardless
// of how valid the rest of the request (client_id/redirect_uri/scope) is.
func TestAuthorizePOST_WrongPassword_NoCodeIssued(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("wrongpw-%d", time.Now().UnixNano()))

	form := baseForm(u.Username, clientID, redirectURI)
	form.Set("password", "definitely-not-the-right-password")
	rec := doAuthorizePOST(t, d, form)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("Location = %q, expected error=access_denied", loc)
	}
	if strings.Contains(loc, "code=") {
		t.Fatalf("Location = %q, no code should be issued for a failed login", loc)
	}
}

// A nonexistent username must fail exactly like a wrong password (no user
// enumeration via a different error/status).
func TestAuthorizePOST_UnknownUsername_SameAccessDeniedAsWrongPassword(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)

	form := baseForm(fmt.Sprintf("no-such-user-%d", time.Now().UnixNano()), clientID, redirectURI)
	rec := doAuthorizePOST(t, d, form)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("Location = %q, expected error=access_denied", loc)
	}
}
