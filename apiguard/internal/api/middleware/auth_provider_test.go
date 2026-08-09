package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/sdk/go/sinauth"
)

// makeJWTWithTyp builds a valid HS256 JWT with an explicit typ claim, so
// tests can exercise the errInvalidTokenType path (typ != "access").
func makeJWTWithTyp(secret, sub, typ string, exp, iat int64) string {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	payload := map[string]interface{}{
		"sub": sub,
		"iat": iat,
		"exp": exp,
		"iss": "apiguard",
		"aud": "apiguard",
		"typ": typ,
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

// ---- ContextWithClaims ----

func TestContextWithClaims(t *testing.T) {
	claims := &Claims{Sub: "carol", Exp: time.Now().Unix() + 3600}
	ctx := ContextWithClaims(context.Background(), claims)

	got, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got != claims {
		t.Error("returned claims pointer does not match stored claims")
	}
}

// ---- sinauthClaimsToLocal ----

func TestSinauthClaimsToLocal_MapsFieldsAndForcesTypAccess(t *testing.T) {
	sc := &sinauth.Claims{
		Sub:       "user-42",
		ExpiresAt: 1700000100,
		IssuedAt:  1700000000,
		Issuer:    "https://sinauth.example.com", // must NOT leak through — Iss is hardcoded
		Role:      "admin",
	}
	got := sinauthClaimsToLocal(sc)

	if got.Sub != "user-42" {
		t.Errorf("Sub: expected user-42, got %q", got.Sub)
	}
	if got.Exp != 1700000100 {
		t.Errorf("Exp: expected 1700000100, got %d", got.Exp)
	}
	if got.Iat != 1700000000 {
		t.Errorf("Iat: expected 1700000000, got %d", got.Iat)
	}
	if got.Iss != "sinauth" {
		t.Errorf("Iss: expected hardcoded %q, got %q", "sinauth", got.Iss)
	}
	if got.Typ != "access" {
		t.Errorf("Typ: expected access, got %q", got.Typ)
	}
	if got.Nbf != 0 {
		t.Errorf("Nbf: expected zero-value (not set by sinauth conversion), got %d", got.Nbf)
	}
	if got.Aud != "" {
		t.Errorf("Aud: expected empty (not carried over), got %q", got.Aud)
	}
}

// ---- isRS256Token ----

func TestIsRS256Token(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{
			name:  "HS256 token is not RS256",
			token: makeJWT("secret", "user", time.Now().Unix()+3600, time.Now().Unix()),
			want:  false,
		},
		{
			name:  "RS256 header",
			token: makeJWTWithAlg("secret", "user", "RS256", time.Now().Unix()+3600, time.Now().Unix()),
			want:  true,
		},
		{
			name:  "malformed token, too few segments",
			token: "onlyonesegment",
			want:  false,
		},
		{
			name:  "invalid base64 header",
			token: "not-base64!.payload.sig",
			want:  false,
		},
		{
			name:  "valid base64 but invalid JSON header",
			token: "bm90anNvbg.payload.sig", // "notjson" base64url-encoded
			want:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRS256Token(tc.token); got != tc.want {
				t.Errorf("isRS256Token(%q) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

// ---- ValidateAccessToken ----

func TestValidateAccessToken(t *testing.T) {
	secret := "access-secret"
	now := time.Now().Unix()
	token := makeJWT(secret, "dave", now+3600, now)

	claims, err := ValidateAccessToken(token, secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Sub != "dave" {
		t.Errorf("Sub = %q, want dave", claims.Sub)
	}

	if _, err := ValidateAccessToken(token, "wrong-secret"); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

// ---- JWTAuthWithProvider / JWTAuthWithProviderAndDenylist ----

func TestJWTAuthWithProvider_ValidToken(t *testing.T) {
	secret := "provider-secret"
	sp := NewSecretProvider(secret)
	now := time.Now().Unix()
	token := makeJWT(secret, "erin", now+3600, now)

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)

	var gotClaims *Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims, _ = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	JWTAuthWithProvider(sp, nil)(next).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if gotClaims == nil || gotClaims.Sub != "erin" {
		t.Fatalf("gotClaims = %+v, want Sub=erin", gotClaims)
	}
}

func TestJWTAuthWithProvider_NoSecretsConfigured(t *testing.T) {
	sp := NewSecretProvider() // empty
	rr := httptest.NewRecorder()
	r := newRequest("Bearer sometoken")
	JWTAuthWithProvider(sp, nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestJWTAuthWithProvider_NoAuthHeader(t *testing.T) {
	sp := NewSecretProvider("secret")
	rr := httptest.NewRecorder()
	JWTAuthWithProvider(sp, nil)(okHandler).ServeHTTP(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestJWTAuthWithProvider_BadHeaderFormat(t *testing.T) {
	sp := NewSecretProvider("secret")
	rr := httptest.NewRecorder()
	r := newRequest("Basic sometoken")
	JWTAuthWithProvider(sp, nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestJWTAuthWithProvider_EmptyToken(t *testing.T) {
	sp := NewSecretProvider("secret")
	rr := httptest.NewRecorder()
	r := newRequest("Bearer ")
	JWTAuthWithProvider(sp, nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestJWTAuthWithProvider_RotatedSecretStillAccepted(t *testing.T) {
	// Token signed with the old secret must still validate during the
	// grace period after Rotate(), because sp.All() tries every secret.
	oldSecret := "old-secret"
	sp := NewSecretProvider(oldSecret)
	now := time.Now().Unix()
	token := makeJWT(oldSecret, "frank", now+3600, now)

	sp.Rotate([]byte("new-secret"))

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuthWithProvider(sp, nil)(okHandler).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (old secret should still verify during grace period)", rr.Code)
	}
}

func TestJWTAuthWithProvider_InvalidTokenType(t *testing.T) {
	sp := NewSecretProvider("secret")
	// Build a token with typ != "access" manually via makeJWTWithAlg-like approach.
	token := makeJWTWithTyp("secret", "user", "refresh", time.Now().Unix()+3600, time.Now().Unix())

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuthWithProvider(sp, nil)(okHandler).ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestJWTAuthWithProviderAndDenylist_DeniedToken(t *testing.T) {
	secret := "denylist-secret"
	sp := NewSecretProvider(secret)
	now := time.Now().Unix()
	token := makeJWT(secret, "gina", now+3600, now)

	d := NewTokenDenylist()
	defer d.Stop()
	d.Add(HashToken(token), time.Now().Add(time.Hour))

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuthWithProviderAndDenylist(sp, d, nil)(okHandler).ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for denylisted token", rr.Code)
	}
}

func TestJWTAuthWithProviderAndDenylist_NonDeniedTokenPasses(t *testing.T) {
	secret := "denylist-secret-2"
	sp := NewSecretProvider(secret)
	now := time.Now().Unix()
	token := makeJWT(secret, "henry", now+3600, now)

	d := NewTokenDenylist()
	defer d.Stop()
	// Deny a different token, not this one.
	d.Add(HashToken("some-other-token"), time.Now().Add(time.Hour))

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuthWithProviderAndDenylist(sp, d, nil)(okHandler).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for non-denylisted token", rr.Code)
	}
}

// ---- JWTAuthWithSinauth / jwtAuthWithSinauthClient HS256 fallback path ----

func TestJWTAuthWithSinauth_EmptyURLFallsBackToHS256(t *testing.T) {
	secret := "sinauth-fallback-secret"
	now := time.Now().Unix()
	token := makeJWT(secret, "irene", now+3600, now)

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	// sinauthURL="" means sc stays nil, so this exercises the HS256-only path.
	JWTAuthWithSinauth(secret, "", nil)(okHandler).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestJWTAuthWithSinauth_NoSecretNoClient(t *testing.T) {
	rr := httptest.NewRecorder()
	r := newRequest("Bearer sometoken")
	JWTAuthWithSinauth("", "", nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestJWTAuthWithRotationAndSinauth_PreviousSecretAccepted(t *testing.T) {
	oldSecret := "old-sinauth-secret"
	newSecret := "new-sinauth-secret"
	now := time.Now().Unix()
	token := makeJWT(oldSecret, "jane", now+3600, now)

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuthWithRotationAndSinauth(newSecret, oldSecret, "", nil)(okHandler).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (previous secret should verify)", rr.Code)
	}
}

// ---- JWTAuthWithProviderDenylistAndSinauth HS256 path (sc=nil) ----

func TestJWTAuthWithProviderDenylistAndSinauth_HS256Path(t *testing.T) {
	secret := "full-variant-secret"
	sp := NewSecretProvider(secret)
	now := time.Now().Unix()
	token := makeJWT(secret, "karl", now+3600, now)

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuthWithProviderDenylistAndSinauth(sp, nil, nil, nil)(okHandler).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestJWTAuthWithProviderDenylistAndSinauth_NoSecretNoClient(t *testing.T) {
	sp := NewSecretProvider()
	rr := httptest.NewRecorder()
	r := newRequest("Bearer sometoken")
	JWTAuthWithProviderDenylistAndSinauth(sp, nil, nil, nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestJWTAuthWithProviderDenylistAndSinauth_DeniedToken(t *testing.T) {
	secret := "full-variant-denylist-secret"
	sp := NewSecretProvider(secret)
	now := time.Now().Unix()
	token := makeJWT(secret, "liam", now+3600, now)

	d := NewTokenDenylist()
	defer d.Stop()
	d.Add(HashToken(token), time.Now().Add(time.Hour))

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuthWithProviderDenylistAndSinauth(sp, d, nil, nil)(okHandler).ServeHTTP(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for denylisted token", rr.Code)
	}
}
