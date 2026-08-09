package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := FromContext(r.Context())
		if ok && c != nil {
			w.Header().Set("X-Sub", c.Sub)
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestMiddlewareMissingTokenProdModeReturns401(t *testing.T) {
	v := NewHS256Verifier([]string{"k"}, "openscrub")
	mw := Middleware(v, false, nil)(okHandler())
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}

func TestMiddlewareMissingTokenDevModeInjectsSyntheticAdmin(t *testing.T) {
	v := NewHS256Verifier([]string{"k"}, "openscrub")
	log := zerolog.Nop()
	mw := Middleware(v, true, &log)(okHandler())
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 in dev mode", rec.Code)
	}
	if got := rec.Header().Get("X-Sub"); got != "dev-anonymous" {
		t.Fatalf("X-Sub = %q, want synthetic dev-anonymous claim", got)
	}
}

func TestMiddlewareInvalidTokenProdModeReturns401(t *testing.T) {
	v := NewHS256Verifier([]string{"k"}, "openscrub")
	mw := Middleware(v, false, nil)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}

func TestMiddlewareInvalidTokenDevModeInjectsSyntheticAdmin(t *testing.T) {
	v := NewHS256Verifier([]string{"k"}, "openscrub")
	log := zerolog.Nop()
	mw := Middleware(v, true, &log)(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 in dev mode", rec.Code)
	}
	if got := rec.Header().Get("X-Sub"); got != "dev-anonymous" {
		t.Fatalf("X-Sub = %q, want synthetic dev-anonymous claim", got)
	}
}

func TestMiddlewareValidTokenSetsClaims(t *testing.T) {
	v := NewHS256Verifier([]string{"k"}, "openscrub")
	mw := Middleware(v, false, nil)(okHandler())
	tok := mintToken(t, "k", "real-user", RoleOperator, "openscrub")
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Sub"); got != "real-user" {
		t.Fatalf("X-Sub = %q, want real-user", got)
	}
}

func TestBearerHeaderParsing(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"empty", "", ""},
		{"valid bearer", "Bearer abc123", "abc123"},
		{"valid bearer with extra spaces trimmed", "Bearer   abc123  ", "abc123"},
		{"wrong scheme basic", "Basic abc123", ""},
		{"lowercase bearer rejected", "bearer abc123", ""},
		{"no scheme prefix", "abc123", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			if got := bearer(req); got != tt.want {
				t.Errorf("bearer(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestAllRoles(t *testing.T) {
	got := AllRoles()
	want := []string{RoleAdmin, RoleOperator, RoleAuditor, RoleAnalyst, RoleReadOnly}
	if len(got) != len(want) {
		t.Fatalf("AllRoles() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AllRoles()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestHasSecrets(t *testing.T) {
	if (&HS256Verifier{}).HasSecrets() {
		t.Fatal("HasSecrets() = true with no secrets configured")
	}
	v := NewHS256Verifier([]string{"a"}, "iss")
	if !v.HasSecrets() {
		t.Fatal("HasSecrets() = false with a secret configured")
	}
	// Empty-string entries must be filtered, not counted.
	v2 := NewHS256Verifier([]string{"", ""}, "iss")
	if v2.HasSecrets() {
		t.Fatal("HasSecrets() = true with only empty-string entries")
	}
}

func TestDevClaimsIsAdmin(t *testing.T) {
	c := devClaims()
	if c.Sub != "dev-anonymous" || c.Role != RoleAdmin {
		t.Fatalf("devClaims() = %+v, want Sub=dev-anonymous Role=admin", c)
	}
}

func TestJwtAlg(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"HS256 token", mintToken(t, "k", "u", RoleAdmin, "iss"), "HS256"},
		{"malformed - too few segments", "onlyonepart", ""},
		{"malformed - bad base64 header", "!!!.body.sig", ""},
		{"malformed - header not json", "bm90anNvbg.body.sig", ""}, // base64("notjson")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jwtAlg(tt.token); got != tt.want {
				t.Errorf("jwtAlg(%q) = %q, want %q", tt.token, got, tt.want)
			}
		})
	}
}

func TestHasRoleNilClaimsOrEmptyRole(t *testing.T) {
	if HasRole(nil, RoleAdmin) {
		t.Fatal("HasRole(nil, ...) = true")
	}
	if HasRole(&Claims{Role: RoleAdmin}, "") {
		t.Fatal("HasRole(c, \"\") = true")
	}
}

func TestHasRoleMatchesRolesSlice(t *testing.T) {
	c := &Claims{Role: RoleReadOnly, Roles: []string{RoleAnalyst, RoleOperator}}
	if !HasRole(c, RoleOperator) {
		t.Fatal("expected HasRole to match against the Roles slice, not just Role")
	}
	if HasRole(c, RoleAdmin) {
		t.Fatal("HasRole matched a role not present in Role or Roles")
	}
}

// TestDualVerifierRoutesRS256ToSinauthAndFails exercises the RS256 code
// path end to end: jwtAlg must detect "RS256" from the header, sinClient
// must lazily construct a sinauth.Client, and — since nothing is
// listening on the loopback port used here — Verify must return an
// error rather than panicking or silently falling back to HS256.
func TestDualVerifierRoutesRS256ToSinauthAndFails(t *testing.T) {
	hs := NewHS256Verifier([]string{"k"}, "openscrub")
	// Port 0 on loopback refuses connections immediately (nothing can
	// ever be listening on it), so this fails fast instead of waiting
	// out sinauth.New's 30s HTTP timeout.
	dv := NewDualVerifier(hs, "http://127.0.0.1:0")

	rs256Header := `{"alg":"RS256","typ":"JWT"}`
	tok := base64URLNoPad(rs256Header) + ".e30." + "sig"

	if got := jwtAlg(tok); got != "RS256" {
		t.Fatalf("jwtAlg did not detect RS256 header: got %q", got)
	}

	_, err := dv.Verify(tok)
	if err == nil {
		t.Fatal("expected an error routing an RS256 token to an unreachable sinauth issuer")
	}
}

// TestDualVerifierFallsThroughToHS256ForNonRS256 confirms non-RS256
// tokens never touch the sinauth path at all.
func TestDualVerifierFallsThroughToHS256ForNonRS256(t *testing.T) {
	hs := NewHS256Verifier([]string{"k"}, "openscrub")
	dv := NewDualVerifier(hs, "http://127.0.0.1:0")
	tok := mintToken(t, "k", "u1", RoleOperator, "openscrub")
	c, err := dv.Verify(tok)
	if err != nil {
		t.Fatalf("expected HS256 fallthrough to succeed, got %v", err)
	}
	if c.Sub != "u1" {
		t.Fatalf("claims = %+v, want Sub=u1", c)
	}
}

func base64URLNoPad(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
