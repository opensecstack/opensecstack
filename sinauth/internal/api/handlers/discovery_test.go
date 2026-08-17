package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/sinauth/internal/oidc"
)

// TestDiscovery_ReturnsSpecRequiredFields proves GET
// /.well-known/openid-configuration exposes the fields the OIDC Discovery
// 1.0 spec (section 3) marks REQUIRED, and that they point at sinauth's own
// endpoints under the configured issuer rather than being left blank.
func TestDiscovery_ReturnsSpecRequiredFields(t *testing.T) {
	issuer := "https://sinauth.test"
	d := Deps{Discovery: oidc.Build(issuer)}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	Discovery(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Errorf("Cache-Control header missing, discovery documents should be cacheable")
	}

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	// OIDC Discovery 1.0 §3 REQUIRED members.
	required := []string{
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"response_types_supported",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
	}
	for _, key := range required {
		v, ok := doc[key]
		if !ok {
			t.Errorf("discovery document missing REQUIRED field %q", key)
			continue
		}
		if s, isStr := v.(string); isStr && s == "" {
			t.Errorf("discovery document field %q is empty string", key)
		}
	}

	if doc["issuer"] != issuer {
		t.Errorf("issuer = %v, want %q", doc["issuer"], issuer)
	}
	if doc["authorization_endpoint"] != issuer+"/oauth/authorize" {
		t.Errorf("authorization_endpoint = %v, want %s/oauth/authorize", doc["authorization_endpoint"], issuer)
	}
	if doc["token_endpoint"] != issuer+"/oauth/token" {
		t.Errorf("token_endpoint = %v, want %s/oauth/token", doc["token_endpoint"], issuer)
	}
	if doc["userinfo_endpoint"] != issuer+"/oauth/userinfo" {
		t.Errorf("userinfo_endpoint = %v, want %s/oauth/userinfo", doc["userinfo_endpoint"], issuer)
	}
	if doc["jwks_uri"] != issuer+"/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %v, want %s/.well-known/jwks.json", doc["jwks_uri"], issuer)
	}
	if doc["revocation_endpoint"] != issuer+"/oauth/token/revoke" {
		t.Errorf("revocation_endpoint = %v, want %s/oauth/token/revoke", doc["revocation_endpoint"], issuer)
	}
	if doc["introspection_endpoint"] != issuer+"/oauth/token/introspect" {
		t.Errorf("introspection_endpoint = %v, want %s/oauth/token/introspect", doc["introspection_endpoint"], issuer)
	}
	if doc["end_session_endpoint"] != issuer+"/oauth/endsession" {
		t.Errorf("end_session_endpoint = %v, want %s/oauth/endsession", doc["end_session_endpoint"], issuer)
	}

	respTypes, ok := doc["response_types_supported"].([]any)
	if !ok || len(respTypes) == 0 || respTypes[0] != "code" {
		t.Errorf("response_types_supported = %v, want [\"code\"]", doc["response_types_supported"])
	}

	algs, ok := doc["id_token_signing_alg_values_supported"].([]any)
	if !ok || len(algs) == 0 || algs[0] != "RS256" {
		t.Errorf("id_token_signing_alg_values_supported = %v, want [\"RS256\"]", doc["id_token_signing_alg_values_supported"])
	}
}

// TestJWKS_ReturnsManagerKeySet proves GET /.well-known/jwks.json serves the
// active signing key from d.Keys, not a stub — the discovery document's
// jwks_uri promises a real, matching key set at this endpoint.
func TestJWKS_ReturnsManagerKeySet(t *testing.T) {
	tmpDir := t.TempDir()
	km := newTestKeyManager(t, tmpDir)
	d := Deps{Keys: km}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	JWKS(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Errorf("Cache-Control header missing")
	}

	var body struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(body.Keys))
	}
	k := body.Keys[0]
	if k.Kty != "RSA" || k.Use != "sig" || k.Alg != "RS256" {
		t.Errorf("unexpected JWK shape: %+v", k)
	}
	if k.N == "" || k.E == "" {
		t.Errorf("JWK modulus/exponent must not be empty: %+v", k)
	}
}
