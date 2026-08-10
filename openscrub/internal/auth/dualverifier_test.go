package auth

// DualVerifier.Verify's RS256 branch delegates to the sinauth SDK,
// which itself does a real HTTP round-trip (OIDC discovery + JWKS).
// These tests stand up a minimal fake sinauth issuer with
// httptest.Server so the RS256 path is exercised end-to-end rather
// than left at the previous 41.7% (HS256-only) coverage.

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
)

// fakeSinauthIssuer serves the two endpoints sinauth.Client.New /
// VerifyToken need: the OIDC discovery document and the JWKS. The
// issuer URL is only known once the server starts, so the discovery
// doc's `issuer` field is patched in after construction.
type fakeSinauthIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newFakeSinauthIssuer(t *testing.T) *fakeSinauthIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	fi := &fakeSinauthIssuer{key: key, kid: "test-kid-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   fi.srv.URL,
			"jwks_uri": fi.srv.URL + "/.well-known/jwks.json",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kid": fi.kid, "kty": "RSA", "alg": "RS256", "n": n, "e": e},
			},
		})
	})
	fi.srv = httptest.NewServer(mux)
	t.Cleanup(fi.srv.Close)
	return fi
}

// mintRS256 signs an RS256 token whose header carries fi.kid and whose
// claims match the shape sinauth.Client.VerifyToken expects (including
// `iss` == the issuer URL, required for the client's own issuer check).
func (fi *fakeSinauthIssuer) mintRS256(t *testing.T, claims map[string]any) string {
	t.Helper()
	mc := jwt.MapClaims{
		"iss": fi.srv.URL,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range claims {
		mc[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, mc)
	tok.Header["kid"] = fi.kid
	s, err := tok.SignedString(fi.key)
	if err != nil {
		t.Fatalf("sign RS256 token: %v", err)
	}
	return s
}

func TestDualVerifierRS256DelegatesToSinauthAndMapsRole(t *testing.T) {
	iss := newFakeSinauthIssuer(t)
	tok := iss.mintRS256(t, map[string]any{
		"sub":  "sin-user-1",
		"role": RoleOperator,
	})

	dv := NewDualVerifier(NewHS256Verifier([]string{"unused"}, ""), iss.srv.URL)
	claims, err := dv.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Sub != "sin-user-1" {
		t.Fatalf("Sub = %q, want sin-user-1", claims.Sub)
	}
	if claims.Role != RoleOperator {
		t.Fatalf("Role = %q, want %q", claims.Role, RoleOperator)
	}
	if claims.Iss != iss.srv.URL {
		t.Fatalf("Iss = %q, want %q", claims.Iss, iss.srv.URL)
	}
}

// TestDualVerifierRS256FallsBackToClientRolesWhenRoleEmpty proves the
// documented fallback: when sinauth's `role` claim is empty but
// `client_roles` is populated, DualVerifier uses the first entry
// rather than leaving Claims.Role empty (which would fail every
// RequireRole check even for a legitimately-scoped caller).
func TestDualVerifierRS256FallsBackToClientRolesWhenRoleEmpty(t *testing.T) {
	iss := newFakeSinauthIssuer(t)
	tok := iss.mintRS256(t, map[string]any{
		"sub":           "sin-user-2",
		"client_roles":  []string{"analyst", "readonly"},
	})

	dv := NewDualVerifier(NewHS256Verifier(nil, ""), iss.srv.URL)
	claims, err := dv.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Role != "analyst" {
		t.Fatalf("Role = %q, want first client_roles entry %q", claims.Role, "analyst")
	}
}

// TestDualVerifierNonRS256FallsThroughToHS256 proves the dispatch
// logic: a token whose header alg isn't RS256 must never touch the
// sinauth client at all — it goes straight to the wrapped
// HS256Verifier. We prove "never touches sinauth" by pointing
// sinauthURL at an address nothing listens on; if the dispatch were
// wrong the test would hang/error trying to reach it instead of
// succeeding immediately via HS256.
func TestDualVerifierNonRS256FallsThroughToHS256(t *testing.T) {
	hs := NewHS256Verifier([]string{"shared-secret"}, "")
	dv := NewDualVerifier(hs, "http://127.0.0.1:1/unreachable-sinauth")

	tok := mintToken(t, "shared-secret", "hs-user", RoleAdmin, "")
	claims, err := dv.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Sub != "hs-user" || claims.Role != RoleAdmin {
		t.Fatalf("claims = %+v, want sub=hs-user role=admin", claims)
	}
}

// TestDualVerifierRS256SinauthUnreachableReturnsWrappedError proves
// that when the RS256 branch's client can't be initialised (bad/
// unreachable sinauth issuer URL) the error is wrapped with the
// documented "auth: sinauth client unavailable: " prefix rather than
// bubbling up sinauth's raw error text — callers and logs depend on
// that prefix to distinguish "sinauth outage" from "bad token".
func TestDualVerifierRS256SinauthUnreachableReturnsWrappedError(t *testing.T) {
	dv := NewDualVerifier(NewHS256Verifier(nil, ""), "http://127.0.0.1:1/unreachable-sinauth")

	// Any syntactically-valid RS256 header routes here; the signature
	// need not verify because sinClient() fails before parsing.
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "x"})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dv.Verify(signed)
	if err == nil {
		t.Fatal("expected an error when sinauth issuer is unreachable")
	}
	const wantPrefix = "auth: sinauth client unavailable: "
	if got := err.Error(); len(got) < len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("error = %q, want prefix %q", got, wantPrefix)
	}
}

// TestJwtAlgReadsHeaderWithoutVerifying covers jwtAlg's parsing
// contract directly, including its malformed-input fallbacks.
func TestJwtAlgReadsHeaderWithoutVerifying(t *testing.T) {
	rsTok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "x"})
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	signed, err := rsTok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if got := jwtAlg(signed); got != "RS256" {
		t.Fatalf("jwtAlg(RS256 token) = %q, want RS256", got)
	}
	if got := jwtAlg("not.a.jwt.four.parts"); got != "" {
		t.Fatalf("jwtAlg(malformed) = %q, want empty", got)
	}
	if got := jwtAlg("not-base64!.x.y"); got != "" {
		t.Fatalf("jwtAlg(bad base64 header) = %q, want empty", got)
	}
}
