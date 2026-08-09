package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// makeJWT builds a valid HS256 JWT for use in tests.
// Pass exp=0 to omit the exp claim (for missing-exp tests).
// iss and aud are set to "apiguard" to match the expected values.
func makeJWT(secret, sub string, exp, iat int64) string {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	payload := map[string]interface{}{
		"sub": sub,
		"iat": iat,
		"iss": "apiguard",
		"aud": "apiguard",
		"typ": "access",
	}
	if exp != 0 {
		payload["exp"] = exp
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

// makeJWTWithAlg builds a JWT with an arbitrary alg field (for wrong-alg tests).
func makeJWTWithAlg(secret, sub, alg string, exp, iat int64) string {
	header := map[string]string{"alg": alg, "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	payload := map[string]interface{}{
		"sub": sub,
		"iat": iat,
		"exp": exp,
		"iss": "apiguard",
		"aud": "apiguard",
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

// okHandler is a simple next handler that writes 200.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func newRequest(authHeader string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/protected", nil)
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	return r
}

// ---- JWTAuth middleware tests ----

func TestJWTAuth_ValidToken(t *testing.T) {
	secret := "test-secret"
	now := time.Now().Unix()
	token := makeJWT(secret, "user-123", now+3600, now)

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)

	var gotClaims *Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims, _ = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	JWTAuth(secret, nil)(next).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotClaims == nil {
		t.Fatal("expected claims in context, got nil")
	}
	if gotClaims.Sub != "user-123" {
		t.Errorf("expected sub=user-123, got %q", gotClaims.Sub)
	}
}

func TestJWTAuth_NoAuthorizationHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	JWTAuth("secret", nil)(okHandler).ServeHTTP(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestJWTAuth_NotBearerScheme(t *testing.T) {
	rr := httptest.NewRecorder()
	r := newRequest("NotBearer sometoken")
	JWTAuth("secret", nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestJWTAuth_EmptyBearerToken(t *testing.T) {
	rr := httptest.NewRecorder()
	r := newRequest("Bearer ")
	JWTAuth("secret", nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestJWTAuth_EmptySecret(t *testing.T) {
	now := time.Now().Unix()
	token := makeJWT("some-secret", "user", now+3600, now)

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuth("", nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when secret is empty, got %d", rr.Code)
	}
}

func TestJWTAuth_ExpiredToken(t *testing.T) {
	secret := "test-secret"
	past := time.Now().Unix() - 7200
	token := makeJWT(secret, "user", past, past-3600)

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuth(secret, nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", rr.Code)
	}
}

func TestJWTAuth_WrongSecret(t *testing.T) {
	now := time.Now().Unix()
	token := makeJWT("correct-secret", "user", now+3600, now)

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuth("wrong-secret", nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong secret, got %d", rr.Code)
	}
}

func TestJWTAuth_MissingSubClaim(t *testing.T) {
	secret := "test-secret"
	now := time.Now().Unix()
	// Build token with empty sub
	token := makeJWT(secret, "", now+3600, now)

	rr := httptest.NewRecorder()
	r := newRequest("Bearer " + token)
	JWTAuth(secret, nil)(okHandler).ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing sub, got %d", rr.Code)
	}
}

// ---- ClaimsFromContext tests ----

func TestClaimsFromContext_Present(t *testing.T) {
	claims := &Claims{Sub: "alice", Exp: time.Now().Unix() + 3600}
	ctx := context.WithValue(context.Background(), claimsKey{}, claims)
	got, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got != claims {
		t.Error("returned claims pointer does not match stored claims")
	}
}

func TestClaimsFromContext_Absent(t *testing.T) {
	_, ok := ClaimsFromContext(context.Background())
	if ok {
		t.Fatal("expected ok=false when no claims in context")
	}
}

// ---- validateJWT tests ----

func TestValidateJWT_ValidToken(t *testing.T) {
	secret := "validate-secret"
	now := time.Now().Unix()
	token := makeJWT(secret, "bob", now+3600, now)

	claims, err := validateJWT(token, secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Sub != "bob" {
		t.Errorf("expected sub=bob, got %q", claims.Sub)
	}
}

func TestValidateJWT_WrongAlgorithm(t *testing.T) {
	secret := "some-secret"
	now := time.Now().Unix()
	// Build a token that claims RS256 in the header.
	token := makeJWTWithAlg(secret, "user", "RS256", now+3600, now)

	_, err := validateJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for RS256 algorithm, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("expected 'unsupported algorithm' error, got: %v", err)
	}
}

func TestValidateJWT_IssuedInFuture(t *testing.T) {
	secret := "some-secret"
	now := time.Now().Unix()
	// iat is more than 60+1 seconds in the future to exceed skew tolerance.
	futureIat := now + 200
	token := makeJWT(secret, "user", now+3600, futureIat)

	_, err := validateJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for future iat, got nil")
	}
	if !strings.Contains(err.Error(), "issued in the future") {
		t.Errorf("expected 'issued in the future' error, got: %v", err)
	}
}

func TestValidateJWT_NotYetValid(t *testing.T) {
	secret := "some-secret"
	now := time.Now().Unix()

	// Build a token with nbf well in the future (beyond the 60s skew window).
	// We construct it manually so we can set the nbf field.
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	payload := map[string]interface{}{
		"sub": "user",
		"iat": now,
		"exp": now + 3600,
		"nbf": now + 300, // 300 seconds in the future — past the 60s skew tolerance
		"iss": "apiguard",
		"aud": "apiguard",
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	token := signingInput + "." + sig

	_, err := validateJWT(token, secret)
	if err == nil {
		t.Fatal("expected error for not-yet-valid token, got nil")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("expected 'not yet valid' error, got: %v", err)
	}
}
