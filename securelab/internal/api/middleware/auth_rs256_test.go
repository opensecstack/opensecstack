// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package middleware_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/opensecstack/securelab/internal/api/middleware"
)

// ---------------------------------------------------------------------------
// A minimal fake sinauth OIDC server, used to exercise the RS256 SSO path in
// Authenticate that the HS256-only tests in auth_test.go never reach (that
// path requires sinauthURL to be non-empty and a real discovery/JWKS
// handshake, which is otherwise untested).
// ---------------------------------------------------------------------------

// newFakeSinauthServer starts an httptest server that serves an OIDC
// discovery document and a JWKS containing the public half of key. Its
// issuer is always its own URL (sinauth.New requires the discovery
// document's issuer to match the URL it was constructed with).
func newFakeSinauthServer(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   server.URL,
				"jwks_uri": server.URL + "/.well-known/jwks.json",
			})
		case "/.well-known/jwks.json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]string{
					{
						"kid": kid,
						"kty": "RSA",
						"alg": "RS256",
						"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
						"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return server
}

// mintRS256JWT signs claims with key under header {"alg":"RS256","kid":kid}.
func mintRS256JWT(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAuthenticate_RS256_ValidTokenGrantsAccess(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := newFakeSinauthServer(t, key, "key-1")
	defer server.Close()

	mw := middleware.Authenticate(testSecret, server.URL)

	var capturedSub, capturedRole string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSub = middleware.SubjectFromContext(r.Context())
		capturedRole = middleware.RoleFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := mw(next)

	tok := mintRS256JWT(t, key, "key-1", jwt.MapClaims{
		"sub":  "sso-user-1",
		"role": "operator",
		"iss":  server.URL,
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iat":  time.Now().Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if capturedSub != "sso-user-1" {
		t.Errorf("sub = %q, want sso-user-1", capturedSub)
	}
	if capturedRole != "operator" {
		t.Errorf("role = %q, want operator", capturedRole)
	}
}

// TestAuthenticate_RS256_WrongIssuerRejected verifies that a token signed by
// a key that IS in the JWKS, but claiming a different issuer than the
// sinauth client was constructed against, is rejected — this guards against
// a token from one tenant/issuer being replayed against another.
func TestAuthenticate_RS256_WrongIssuerRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := newFakeSinauthServer(t, key, "key-1")
	defer server.Close()

	mw := middleware.Authenticate(testSecret, server.URL)
	h := mw(okHandler)

	tok := mintRS256JWT(t, key, "key-1", jwt.MapClaims{
		"sub":  "sso-user-1",
		"role": "operator",
		"iss":  "https://attacker-issuer.example",
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iat":  time.Now().Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for issuer mismatch, got %d", rr.Code)
	}
}

// TestAuthenticate_RS256_UnknownKidRejected verifies that a token whose kid
// is not present in the JWKS (e.g. an attacker-controlled key never
// published by sinauth) is rejected rather than silently accepted.
func TestAuthenticate_RS256_UnknownKidRejected(t *testing.T) {
	knownKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := newFakeSinauthServer(t, knownKey, "key-1")
	defer server.Close()

	mw := middleware.Authenticate(testSecret, server.URL)
	h := mw(okHandler)

	// Signed with a key that is never published in the JWKS, but references
	// a kid that isn't in the key set either.
	tok := mintRS256JWT(t, attackerKey, "unknown-kid", jwt.MapClaims{
		"sub":  "attacker",
		"role": "admin",
		"iss":  server.URL,
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iat":  time.Now().Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unknown kid, got %d", rr.Code)
	}
}

// TestAuthenticate_RS256_MissingSubRejected verifies that even a
// successfully verified RS256 token is rejected if it carries no subject
// claim, mirroring the HS256 path's requirement.
func TestAuthenticate_RS256_MissingSubRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := newFakeSinauthServer(t, key, "key-1")
	defer server.Close()

	mw := middleware.Authenticate(testSecret, server.URL)
	h := mw(okHandler)

	tok := mintRS256JWT(t, key, "key-1", jwt.MapClaims{
		// no "sub"
		"role": "operator",
		"iss":  server.URL,
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iat":  time.Now().Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing sub in RS256 token, got %d", rr.Code)
	}
}

// TestAuthenticate_RS256_EmptyRoleAllowedForServiceAccounts verifies the
// documented behaviour that an RS256 token with sub set but role empty
// (service-account tokens) is accepted by Authenticate — RequireRole is
// responsible for denying it further downstream, not Authenticate itself.
func TestAuthenticate_RS256_EmptyRoleAllowedForServiceAccounts(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := newFakeSinauthServer(t, key, "key-1")
	defer server.Close()

	mw := middleware.Authenticate(testSecret, server.URL)

	var capturedRole string
	seenRole := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRole = middleware.RoleFromContext(r.Context())
		seenRole = true
		w.WriteHeader(http.StatusOK)
	})
	h := mw(next)

	tok := mintRS256JWT(t, key, "key-1", jwt.MapClaims{
		"sub":  "service-account-1",
		"iss":  server.URL,
		"exp":  time.Now().Add(time.Hour).Unix(),
		"iat":  time.Now().Unix(),
		// no "role"
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-account token with empty role, got %d", rr.Code)
	}
	if !seenRole {
		t.Fatal("handler was never called")
	}
	if capturedRole != "" {
		t.Errorf("role = %q, want empty string for service-account token", capturedRole)
	}
}

// TestAuthenticate_RS256_ExpiredTokenRejected exercises the standard JWT
// expiration check on the RS256/sinauth path.
func TestAuthenticate_RS256_ExpiredTokenRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := newFakeSinauthServer(t, key, "key-1")
	defer server.Close()

	mw := middleware.Authenticate(testSecret, server.URL)
	h := mw(okHandler)

	tok := mintRS256JWT(t, key, "key-1", jwt.MapClaims{
		"sub":  "sso-user-1",
		"role": "operator",
		"iss":  server.URL,
		"exp":  time.Now().Add(-time.Hour).Unix(), // expired
		"iat":  time.Now().Add(-2 * time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired RS256 token, got %d", rr.Code)
	}
}
