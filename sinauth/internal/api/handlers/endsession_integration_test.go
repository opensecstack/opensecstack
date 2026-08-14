//go:build integration

package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEndSession_RegisteredRedirectURI_IsHonoured proves the fixed-and-secure
// path: post_logout_redirect_uri IS followed when client_id identifies a
// real client and the URI is exactly in that client's registered
// redirect_uris allowlist — the same allowlist /oauth/authorize enforces.
func TestEndSession_RegisteredRedirectURI_IsHonoured(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)

	target := "https://client.test/logged-out"
	clientID := createTestOAuthClient(t, d, target)

	req := httptest.NewRequest(http.MethodGet, "/oauth/endsession?client_id="+clientID+"&post_logout_redirect_uri="+target, nil)
	rec := httptest.NewRecorder()
	EndSession(d)(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if loc := rec.Header().Get("Location"); loc != target {
		t.Errorf("Location = %q, want registered redirect %q", loc, target)
	}
}

// TestEndSession_UnregisteredRedirectURI_FallsBackToSiteURL proves that even
// with a valid client_id, a post_logout_redirect_uri NOT in that client's
// registered redirect_uris is rejected — the open-redirect check is a real
// allowlist match, not just "any client_id present".
func TestEndSession_UnregisteredRedirectURI_FallsBackToSiteURL(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)

	clientID := createTestOAuthClient(t, d, "https://client.test/logged-out")
	evil := "https://evil.example/phish"

	req := httptest.NewRequest(http.MethodGet, "/oauth/endsession?client_id="+clientID+"&post_logout_redirect_uri="+evil, nil)
	rec := httptest.NewRecorder()
	EndSession(d)(rec, req)

	if loc := rec.Header().Get("Location"); loc != d.Cfg.SiteURL {
		t.Errorf("Location = %q, want fallback to SiteURL %q — unregistered URI must not be honoured even with a valid client_id", loc, d.Cfg.SiteURL)
	}
}

// TestEndSession_UnknownClientID_FallsBackToSiteURL proves a nonexistent
// client_id (not just a missing one) also fails closed.
func TestEndSession_UnknownClientID_FallsBackToSiteURL(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)

	target := "https://client.test/logged-out"
	req := httptest.NewRequest(http.MethodGet, "/oauth/endsession?client_id=does-not-exist&post_logout_redirect_uri="+target, nil)
	rec := httptest.NewRecorder()
	EndSession(d)(rec, req)

	if loc := rec.Header().Get("Location"); loc != d.Cfg.SiteURL {
		t.Errorf("Location = %q, want fallback to SiteURL %q for an unknown client_id", loc, d.Cfg.SiteURL)
	}
}
