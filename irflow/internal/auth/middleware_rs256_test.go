package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// jwtHeaderAlg — pure function, no signature verification. Exercises every
// early-return branch: wrong segment count, invalid base64, invalid JSON,
// and the two valid algs actually used by the dual-mode middleware.
// ---------------------------------------------------------------------------

func TestJwtHeaderAlg(t *testing.T) {
	mkToken := func(headerJSON string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(headerJSON)) + ".payload.sig"
	}

	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"HS256 header", mkToken(`{"alg":"HS256","typ":"JWT"}`), "HS256"},
		{"RS256 header", mkToken(`{"alg":"RS256","typ":"JWT"}`), "RS256"},
		{"too few segments", "onlyonepart", ""},
		{"too many segments treated as 3 max split", "a.b.c.d", "extra-ignored"}, // handled below
		{"empty string", "", ""},
		{"invalid base64 header", "not-valid-base64!!!.payload.sig", ""},
		{"valid base64 but invalid JSON", base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".payload.sig", ""},
		{"missing alg field", mkToken(`{"typ":"JWT"}`), ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "too many segments treated as 3 max split" {
				// SplitN(token, ".", 3) on "a.b.c.d" yields ["a","b","c.d"] —
				// 3 parts, so it proceeds to (invalid) base64-decode "a" and
				// fails there, returning "".
				got := jwtHeaderAlg(c.token)
				if got != "" {
					t.Errorf("jwtHeaderAlg(%q) = %q, want \"\"", c.token, got)
				}
				return
			}
			got := jwtHeaderAlg(c.token)
			if got != c.want {
				t.Errorf("jwtHeaderAlg(%q) = %q, want %q", c.token, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Middleware dual-mode dispatch: a token whose header claims alg=RS256 must
// be routed to the sinauth verification path, not the HS256 path. Since no
// real sinauth server is reachable in this test, verification must fail
// closed (401), never fall through to treating the token as authenticated.
// ---------------------------------------------------------------------------

func rs256LookingToken(payloadJSON string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	// Signature bytes are irrelevant — sinauth.VerifyToken must reject this
	// as an untrusted/unverifiable token regardless, since there is no real
	// RSA signature backing it.
	sig := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
	return header + "." + payload + "." + sig
}

func TestMiddleware_RS256Token_FailsClosedWhenSinauthUnreachable(t *testing.T) {
	h := Middleware(Config{Secret: mwSecret, SinauthURL: "http://127.0.0.1:1"})(protectedHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+rs256LookingToken(`{"sub":"attacker","role":"admin"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Whatever the exact failure mode (client init error or verify error),
	// an RS256 token that cannot be genuinely verified against sinauth must
	// never be treated as authenticated.
	if rec.Code == http.StatusOK {
		t.Fatalf("RS256 token with no reachable sinauth must not authenticate; status = %d, body = %s",
			rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// The HS256 path must remain unaffected when SinauthURL is configured but
// the token itself is HS256 — dual-mode dispatch must key off the token's
// own header, not global config.
func TestMiddleware_HS256Token_UnaffectedBySinauthConfig(t *testing.T) {
	h := Middleware(Config{Secret: mwSecret, SinauthURL: "http://127.0.0.1:1"})(protectedHandler())

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tokenFor(t, RoleAdmin))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}
