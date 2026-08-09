package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoverOIDC_ParsesDiscoveryDocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("unexpected discovery path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(OIDCDiscovery{
			AuthorizationEndpoint: "https://upstream.example/authorize",
			TokenEndpoint:         "https://upstream.example/token",
			UserinfoEndpoint:      "https://upstream.example/userinfo",
		})
	}))
	defer srv.Close()

	doc, err := DiscoverOIDC(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("DiscoverOIDC: %v", err)
	}
	if doc.AuthorizationEndpoint != "https://upstream.example/authorize" {
		t.Errorf("AuthorizationEndpoint = %q", doc.AuthorizationEndpoint)
	}
	if doc.TokenEndpoint != "https://upstream.example/token" {
		t.Errorf("TokenEndpoint = %q", doc.TokenEndpoint)
	}
	if doc.UserinfoEndpoint != "https://upstream.example/userinfo" {
		t.Errorf("UserinfoEndpoint = %q", doc.UserinfoEndpoint)
	}
}

// TestDiscoverOIDC_TrimsTrailingSlash proves the issuer's trailing slash
// (if any) is normalized before appending the well-known path, avoiding a
// double-slash URL that some providers would reject.
func TestDiscoverOIDC_TrimsTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(OIDCDiscovery{})
	}))
	defer srv.Close()

	if _, err := DiscoverOIDC(context.Background(), srv.URL+"/"); err != nil {
		t.Fatalf("DiscoverOIDC: %v", err)
	}
	if gotPath != "/.well-known/openid-configuration" {
		t.Errorf("request path = %q, want no double slash", gotPath)
	}
}

func TestDiscoverOIDC_PropagatesHTTPError(t *testing.T) {
	// Use a URL with no listener to force a network-level error.
	_, err := DiscoverOIDC(context.Background(), "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("DiscoverOIDC: expected error when upstream is unreachable, got nil")
	}
}

func TestBuildAuthURL(t *testing.T) {
	discovery := &OIDCDiscovery{AuthorizationEndpoint: "https://upstream.example/authorize"}
	p := &Provider{
		OIDCClientID: "client-abc",
		OIDCScopes:   []string{"openid", "email"},
	}

	got := BuildAuthURL(discovery, p, "state-123", "nonce-456", "https://sin.to/callback")

	if !strings.HasPrefix(got, "https://upstream.example/authorize?") {
		t.Fatalf("BuildAuthURL = %q, want prefix https://upstream.example/authorize?", got)
	}
	for _, want := range []string{
		"response_type=code",
		"client_id=client-abc",
		"state=state-123",
		"nonce=nonce-456",
		"scope=openid+email",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("BuildAuthURL = %q, want it to contain %q", got, want)
		}
	}
}

func TestExchangeOIDCCode_ReturnsUserinfoClaims(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q, want authorization_code", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code") != "auth-code-1" {
			t.Errorf("code = %q, want auth-code-1", r.Form.Get("code"))
		}
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "at-1",
			"id_token":     "idtok-1",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer at-1" {
			t.Errorf("Authorization = %q, want Bearer at-1", auth)
		}
		json.NewEncoder(w).Encode(OIDCUpstreamClaims{
			Sub:   "upstream-sub-1",
			Email: "user@upstream.example",
			Name:  "Upstream User",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	discovery := &OIDCDiscovery{
		TokenEndpoint:    srv.URL + "/token",
		UserinfoEndpoint: srv.URL + "/userinfo",
	}
	p := &Provider{OIDCClientID: "client-abc", OIDCClientSecret: "secret-xyz"}

	claims, err := ExchangeOIDCCode(context.Background(), discovery, p, "auth-code-1", "https://sin.to/callback")
	if err != nil {
		t.Fatalf("ExchangeOIDCCode: %v", err)
	}
	if claims.Sub != "upstream-sub-1" {
		t.Errorf("Sub = %q, want upstream-sub-1", claims.Sub)
	}
	if claims.Email != "user@upstream.example" {
		t.Errorf("Email = %q, want user@upstream.example", claims.Email)
	}
	if claims.Name != "Upstream User" {
		t.Errorf("Name = %q, want Upstream User", claims.Name)
	}
}

func TestGenerateState_ReturnsNonEmptyUniqueValues(t *testing.T) {
	s1, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	s2, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	if s1 == "" || s2 == "" {
		t.Fatal("GenerateState returned an empty string")
	}
	if s1 == s2 {
		t.Error("GenerateState returned identical values on consecutive calls (should be random)")
	}
}
