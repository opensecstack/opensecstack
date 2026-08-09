package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func signHS256(t *testing.T, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("signHS256: %v", err)
	}
	return signed
}

func TestNewHS256Verifier_FiltersEmptySecrets(t *testing.T) {
	v := NewHS256Verifier([]string{"", "s1", "", "s2"}, "iss")
	if !v.HasSecrets() {
		t.Fatalf("HasSecrets: want true")
	}
	if len(v.secrets) != 2 {
		t.Fatalf("secrets: got %d, want 2", len(v.secrets))
	}
}

func TestHS256Verifier_HasSecrets_FalseWhenNone(t *testing.T) {
	v := NewHS256Verifier(nil, "iss")
	if v.HasSecrets() {
		t.Fatalf("HasSecrets: want false for empty secrets")
	}
}

func TestHS256Verifier_Verify_EmptyToken(t *testing.T) {
	v := NewHS256Verifier([]string{"secret"}, "")
	if _, err := v.Verify(""); err == nil {
		t.Fatalf("Verify(\"\"): want error")
	}
}

func TestHS256Verifier_Verify_NoSecretsConfigured(t *testing.T) {
	v := NewHS256Verifier(nil, "")
	if _, err := v.Verify("sometoken"); err == nil {
		t.Fatalf("Verify: want error when no secrets configured")
	}
}

func TestHS256Verifier_Verify_ValidToken(t *testing.T) {
	secret := []byte("shared-secret")
	v := NewHS256Verifier([]string{"shared-secret"}, "")
	tok := signHS256(t, secret, jwt.MapClaims{
		"sub":  "user-1",
		"role": RoleAdmin,
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if claims.Sub != "user-1" || claims.Role != RoleAdmin {
		t.Fatalf("Verify: got claims %+v", claims)
	}
}

func TestHS256Verifier_Verify_TriesSecretsInPriorityOrder(t *testing.T) {
	// Token signed with the "previous" secret should still verify when
	// listed second, exercising the multi-secret fallback loop.
	v := NewHS256Verifier([]string{"primary", "previous"}, "")
	tok := signHS256(t, []byte("previous"), jwt.MapClaims{
		"sub": "user-2",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if claims.Sub != "user-2" {
		t.Fatalf("Verify: got sub=%q, want user-2", claims.Sub)
	}
}

func TestHS256Verifier_Verify_WrongSecretFails(t *testing.T) {
	v := NewHS256Verifier([]string{"only-secret"}, "")
	tok := signHS256(t, []byte("different-secret"), jwt.MapClaims{"sub": "u"})
	if _, err := v.Verify(tok); err == nil {
		t.Fatalf("Verify: want error for token signed with unknown secret")
	}
}

func TestHS256Verifier_Verify_IssuerMismatch(t *testing.T) {
	secret := []byte("secret")
	v := NewHS256Verifier([]string{"secret"}, "expected-issuer")
	tok := signHS256(t, secret, jwt.MapClaims{
		"sub": "u",
		"iss": "other-issuer",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := v.Verify(tok); err == nil {
		t.Fatalf("Verify: want error for issuer mismatch")
	}
}

func TestHS256Verifier_Verify_RejectsNonHMACAlg(t *testing.T) {
	// jwt.Parse with the HS256 verifier's keyfunc should reject RS256-alg
	// tokens outright (defence against alg-confusion attacks).
	v := NewHS256Verifier([]string{"secret"}, "")
	// A syntactically-valid but unsigned/garbage RS256-header token.
	rs256ish := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1In0.garbage"
	if _, err := v.Verify(rs256ish); err == nil {
		t.Fatalf("Verify: want error for non-HMAC alg token")
	}
}

func TestJwtHeaderAlg(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"HS256 token", signHS256(t, []byte("k"), jwt.MapClaims{"sub": "u"}), "HS256"},
		{"malformed - too few segments", "not.a.jwt.at.all.extra", ""},
		{"malformed - bad base64 header", "!!!.body.sig", ""},
		{"malformed - header not json", base64URLNoPad("notjson") + ".body.sig", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jwtHeaderAlg(tc.token); got != tc.want {
				t.Fatalf("jwtHeaderAlg(%q) = %q, want %q", tc.token, got, tc.want)
			}
		})
	}
}

func base64URLNoPad(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	// Minimal manual base64url encode (avoids importing encoding/base64 twice
	// with different padding modes in the test); good enough for a fixed
	// short literal used only to build a "not JSON" header segment.
	var out []byte
	var val, bits int
	for i := 0; i < len(s); i++ {
		val = (val << 8) | int(s[i])
		bits += 8
		for bits >= 6 {
			bits -= 6
			out = append(out, alphabet[(val>>bits)&0x3F])
		}
	}
	if bits > 0 {
		out = append(out, alphabet[(val<<(6-bits))&0x3F])
	}
	return string(out)
}

func TestFromContextAndWithClaims_RoundTrip(t *testing.T) {
	c := &Claims{Sub: "u1"}
	ctx := WithClaims(t.Context(), c)
	got, ok := FromContext(ctx)
	if !ok || got != c {
		t.Fatalf("FromContext: got=%v ok=%v", got, ok)
	}
}

func TestFromContext_MissingReturnsFalse(t *testing.T) {
	if _, ok := FromContext(t.Context()); ok {
		t.Fatalf("FromContext: want ok=false on empty context")
	}
}

func TestDualVerifier_NonRS256DelegatesToHS256(t *testing.T) {
	secret := []byte("secret")
	hs := NewHS256Verifier([]string{"secret"}, "")
	d := NewDualVerifier(hs, "")
	tok := signHS256(t, secret, jwt.MapClaims{"sub": "u1", "exp": time.Now().Add(time.Hour).Unix()})
	claims, err := d.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if claims.Sub != "u1" {
		t.Fatalf("Verify: got sub=%q", claims.Sub)
	}
}

func TestDualVerifier_RS256WithoutSinauthURLFails(t *testing.T) {
	d := NewDualVerifier(NewHS256Verifier(nil, ""), "")
	// Header alg=RS256, body/sig irrelevant since URL check short-circuits.
	rs256Header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	tok := rs256Header + ".eyJzdWIiOiJ1In0.sig"
	if _, err := d.Verify(tok); err == nil {
		t.Fatalf("Verify: want error when sinauthURL unconfigured for RS256 token")
	}
}

func TestDualVerifier_RS256SinauthUnreachableFails(t *testing.T) {
	// A server that 404s the discovery document, forcing sinauth.New to fail
	// fast and deterministically without touching the real network.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	d := NewDualVerifier(NewHS256Verifier(nil, ""), srv.URL)
	rs256Header := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
	tok := rs256Header + ".eyJzdWIiOiJ1In0.sig"
	_, err := d.Verify(tok)
	if err == nil {
		t.Fatalf("Verify: want error when sinauth discovery is unreachable")
	}
}

func TestBearer(t *testing.T) {
	cases := []struct {
		name string
		hdr  string
		want string
	}{
		{"bearer prefix", "Bearer abc123", "abc123"},
		{"bearer prefix with extra space", "Bearer   abc123", "abc123"},
		{"no header", "", ""},
		{"raw token, no prefix", "abc123", "abc123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.hdr != "" {
				req.Header.Set("Authorization", tc.hdr)
			}
			if got := bearer(req); got != tc.want {
				t.Fatalf("bearer() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMiddleware_DevMode_MissingTokenPassesThrough(t *testing.T) {
	v := NewHS256Verifier([]string{"secret"}, "")
	h := Middleware(v, true, nil)(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dev mode, missing token: want 200, got %d", rec.Code)
	}
}

func TestMiddleware_DevMode_InvalidTokenPassesThrough(t *testing.T) {
	v := NewHS256Verifier([]string{"secret"}, "")
	h := Middleware(v, true, nil)(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dev mode, invalid token: want 200, got %d", rec.Code)
	}
}

func TestMiddleware_ProdMode_MissingTokenFailsClosed(t *testing.T) {
	v := NewHS256Verifier([]string{"secret"}, "")
	h := Middleware(v, false, nil)(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("prod mode, missing token: want 401, got %d", rec.Code)
	}
}

func TestMiddleware_ProdMode_InvalidTokenFailsClosed(t *testing.T) {
	v := NewHS256Verifier([]string{"secret"}, "")
	h := Middleware(v, false, nil)(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("prod mode, invalid token: want 401, got %d", rec.Code)
	}
}

func TestMiddleware_ProdMode_ValidTokenStashesClaims(t *testing.T) {
	secret := []byte("secret")
	v := NewHS256Verifier([]string{"secret"}, "")
	var gotClaims *Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(v, false, nil)(next)

	tok := signHS256(t, secret, jwt.MapClaims{"sub": "u1", "role": RoleAdmin, "exp": time.Now().Add(time.Hour).Unix()})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: want 200, got %d", rec.Code)
	}
	if gotClaims == nil || gotClaims.Sub != "u1" {
		t.Fatalf("Middleware: claims not stashed correctly, got %+v", gotClaims)
	}
}
