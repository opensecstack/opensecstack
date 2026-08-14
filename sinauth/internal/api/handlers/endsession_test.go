package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/sinauth/internal/config"
)

// TestEndSession_NoRedirectURI_FallsBackToSiteURL proves that when the
// client omits post_logout_redirect_uri, sinauth does not leave the browser
// on a blank page or error — it falls back to the configured SiteURL rather
// than, say, echoing an unvalidated URL.
func TestEndSession_NoRedirectURI_FallsBackToSiteURL(t *testing.T) {
	d := Deps{Cfg: &config.Config{SiteURL: "https://sinauth.test", DevMode: true}}
	req := httptest.NewRequest(http.MethodGet, "/oauth/endsession", nil)
	rec := httptest.NewRecorder()
	EndSession(d)(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if loc := rec.Header().Get("Location"); loc != d.Cfg.SiteURL {
		t.Errorf("Location = %q, want %q", loc, d.Cfg.SiteURL)
	}
}

// TestEndSession_UnvalidatedRedirectURI_FallsBackToSiteURL is an open-redirect
// regression test: post_logout_redirect_uri is attacker-controlled query
// input. Without a client_id identifying which client's registered
// redirect_uris to check it against (and without a ClientSvc wired at all,
// as here), EndSession must never follow it — it must fall back to SiteURL,
// not redirect to an arbitrary attacker-supplied URL.
func TestEndSession_UnvalidatedRedirectURI_FallsBackToSiteURL(t *testing.T) {
	d := Deps{Cfg: &config.Config{SiteURL: "https://sinauth.test", DevMode: true}}
	evil := "https://evil.example/phish"
	req := httptest.NewRequest(http.MethodGet, "/oauth/endsession?post_logout_redirect_uri="+evil, nil)
	rec := httptest.NewRecorder()
	EndSession(d)(rec, req)

	if loc := rec.Header().Get("Location"); loc != d.Cfg.SiteURL {
		t.Errorf("Location = %q, want fallback to SiteURL %q (open redirect if this is the attacker URL)", loc, d.Cfg.SiteURL)
	}
}

// TestEndSession_DevMode_CookieNotSecure proves the Secure flag tracks
// DevMode so local HTTP development still works (browsers drop Secure
// cookies over plain HTTP).
func TestEndSession_DevMode_CookieNotSecure(t *testing.T) {
	d := Deps{Cfg: &config.Config{SiteURL: "https://sinauth.test", DevMode: true}}
	req := httptest.NewRequest(http.MethodGet, "/oauth/endsession", nil)
	rec := httptest.NewRecorder()
	EndSession(d)(rec, req)

	for _, c := range rec.Result().Cookies() {
		if c.Name == "sinauth_session" && c.Secure {
			t.Errorf("sinauth_session must not be Secure in DevMode (breaks local HTTP dev)")
		}
	}
}

// TestEndSession_ClearsCookie proves the SSO session cookie is actively
// cleared (MaxAge<0), not just left alone, regardless of redirect target.
func TestEndSession_ClearsCookie(t *testing.T) {
	d := Deps{Cfg: &config.Config{SiteURL: "https://sinauth.test", DevMode: false}}
	req := httptest.NewRequest(http.MethodGet, "/oauth/endsession", nil)
	rec := httptest.NewRecorder()
	EndSession(d)(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sinauth_session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected sinauth_session cookie to be set (cleared) in the response")
	}
	if sessionCookie.MaxAge >= 0 {
		t.Errorf("sinauth_session MaxAge = %d, want negative (cookie deletion)", sessionCookie.MaxAge)
	}
	if sessionCookie.Value != "" {
		t.Errorf("sinauth_session Value = %q, want empty", sessionCookie.Value)
	}
	if !sessionCookie.HttpOnly {
		t.Errorf("sinauth_session must be HttpOnly")
	}
	if !sessionCookie.Secure {
		t.Errorf("sinauth_session must be Secure when DevMode is false")
	}
}
