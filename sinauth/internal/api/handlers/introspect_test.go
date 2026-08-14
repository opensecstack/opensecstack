//go:build integration

package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/sinauth/internal/token"
)

// introspectDeps builds a Deps with a real Issuer+Verifier pair sharing one
// RSA key, so tests can mint tokens Introspect will actually validate.
func introspectDeps(t *testing.T) (Deps, *token.Issuer) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	issuer := token.NewIssuer(key, "test-kid", "https://sinauth.test")
	verifier := token.NewVerifier(&key.PublicKey, "https://sinauth.test")
	return Deps{Verifier: verifier}, issuer
}

func doIntrospectRequest(t *testing.T, d Deps, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token/introspect", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	Introspect(d)(rec, req)
	return rec
}

func decodeIntrospectResponse(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v (body=%s)", err, rec.Body.String())
	}
	return body
}

// TestIntrospect_ValidToken_ReturnsActiveWithClaims proves a genuine,
// unexpired access token round-trips through introspection with its claims
// (RFC 7662 §2.2), the way a resource server relies on to authorize a call.
func TestIntrospect_ValidToken_ReturnsActiveWithClaims(t *testing.T) {
	d, issuer := introspectDeps(t)
	tok, err := issuer.IssueAccessToken("alice", "test-client", []string{"openid", "profile"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	rec := doIntrospectRequest(t, d, "token="+tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeIntrospectResponse(t, rec)
	if body["active"] != true {
		t.Fatalf("active = %v, want true", body["active"])
	}
	if body["sub"] != "alice" {
		t.Errorf("sub = %v, want alice", body["sub"])
	}
	if body["client_id"] != "test-client" {
		t.Errorf("client_id = %v, want test-client", body["client_id"])
	}
	if body["scope"] != "openid profile" {
		t.Errorf("scope = %v, want %q", body["scope"], "openid profile")
	}
	if body["iss"] != "https://sinauth.test" {
		t.Errorf("iss = %v, want https://sinauth.test", body["iss"])
	}
	if _, ok := body["exp"]; !ok {
		t.Error("exp missing from response")
	}
}

// TestIntrospect_ExpiredToken_ReturnsActiveFalse proves an expired token is
// reported inactive per RFC 7662, not merely echoed back as-is.
func TestIntrospect_ExpiredToken_ReturnsActiveFalse(t *testing.T) {
	d, issuer := introspectDeps(t)
	tok, err := issuer.IssueAccessToken("bob", "test-client", []string{"openid"}, -time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	rec := doIntrospectRequest(t, d, "token="+tok)
	assertInactiveOnly(t, rec)
}

// TestIntrospect_MalformedToken_ReturnsActiveFalse proves garbage input
// degrades to {"active": false} rather than a 4xx/5xx error — RFC 7662 §2.2
// requires a 200 response with active:false for any token the AS cannot
// validate, so callers can't distinguish "malformed" from "expired" from
// "revoked" by response shape or status code.
func TestIntrospect_MalformedToken_ReturnsActiveFalse(t *testing.T) {
	d, _ := introspectDeps(t)
	rec := doIntrospectRequest(t, d, "token=not-a-jwt-at-all")
	assertInactiveOnly(t, rec)
}

// TestIntrospect_MissingToken_ReturnsActiveFalse proves an empty/absent
// token parameter is handled the same non-committal way rather than a 400 —
// RFC 7662 doesn't mandate this, but it must not crash or 500.
func TestIntrospect_MissingToken_ReturnsActiveFalse(t *testing.T) {
	d, _ := introspectDeps(t)
	rec := doIntrospectRequest(t, d, "")
	assertInactiveOnly(t, rec)
}

// TestIntrospect_TokenFromDifferentIssuer_ReturnsActiveFalse proves a
// validly-signed-but-wrong-issuer token (e.g. forged against a different
// key, or replayed from another sinauth deployment) is rejected.
func TestIntrospect_TokenFromDifferentIssuer_ReturnsActiveFalse(t *testing.T) {
	d, _ := introspectDeps(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	otherIssuer := token.NewIssuer(otherKey, "other-kid", "https://attacker.test")
	tok, err := otherIssuer.IssueAccessToken("mallory", "test-client", []string{"openid"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	rec := doIntrospectRequest(t, d, "token="+tok)
	assertInactiveOnly(t, rec)
}

// assertInactiveOnly asserts the introspection response is exactly
// {"active": false} with no leaked claims — RFC 7662 §2.3 requires the
// server not to disclose whether the presented token exists, was revoked,
// expired, or is simply malformed. A response that includes sub/client_id/
// scope alongside active:false, or that differs in status code between
// these cases, is an information-disclosure defect.
func assertInactiveOnly(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (RFC 7662 requires 200 even for inactive tokens); body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeIntrospectResponse(t, rec)
	if body["active"] != false {
		t.Fatalf("active = %v, want false", body["active"])
	}
	for _, leaked := range []string{"sub", "client_id", "scope", "exp", "iat", "iss"} {
		if _, present := body[leaked]; present {
			t.Errorf("inactive-token response leaked claim %q: %v (information disclosure)", leaked, body)
		}
	}
}
