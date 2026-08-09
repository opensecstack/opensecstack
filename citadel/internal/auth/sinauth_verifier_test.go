package auth

import (
	"context"
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

// fakeSinauth spins up a local HTTP server serving OIDC discovery + JWKS
// documents shaped like a real sinauth instance, so SinauthVerifier can be
// tested without a live sinauth deployment or network access.
type fakeSinauth struct {
	server *httptest.Server
	priv   *rsa.PrivateKey
	kid    string
}

func newFakeSinauth(t *testing.T) *fakeSinauth {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	f := &fakeSinauth{priv: priv, kid: "test-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   f.server.URL,
			"jwks_uri": f.server.URL + "/.well-known/jwks.json",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kid": f.kid, "kty": "RSA", "alg": "RS256", "n": n, "e": e},
			},
		})
	})

	f.server = httptest.NewServer(mux)
	return f
}

func (f *fakeSinauth) close() { f.server.Close() }

// issueToken signs a JWT the way sinauth would, with the given subject/role
// and expiry.
func (f *fakeSinauth) issueToken(t *testing.T, sub, role string, expiresIn time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":  sub,
		"role": role,
		"iss":  f.server.URL,
		"aud":  []string{"citadel"},
		"iat":  now.Unix(),
		"exp":  now.Add(expiresIn).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = f.kid
	signed, err := token.SignedString(f.priv)
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}
	return signed
}

func TestSinauthVerifier_ValidToken(t *testing.T) {
	fake := newFakeSinauth(t)
	defer fake.close()

	v, err := NewSinauthVerifier(fake.server.URL)
	if err != nil {
		t.Fatalf("NewSinauthVerifier: %v", err)
	}

	token := fake.issueToken(t, "user-uuid-123", "operator", time.Hour)
	userID, role, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if userID != "user-uuid-123" {
		t.Errorf("userID = %q, want %q", userID, "user-uuid-123")
	}
	if role != "operator" {
		t.Errorf("role = %q, want %q", role, "operator")
	}
}

func TestSinauthVerifier_ExpiredToken(t *testing.T) {
	fake := newFakeSinauth(t)
	defer fake.close()

	v, err := NewSinauthVerifier(fake.server.URL)
	if err != nil {
		t.Fatalf("NewSinauthVerifier: %v", err)
	}

	token := fake.issueToken(t, "user-uuid-123", "operator", -time.Hour) // already expired
	if _, _, err := v.Verify(context.Background(), token); err == nil {
		t.Error("Verify should reject an expired token")
	}
}

func TestSinauthVerifier_WrongSigningKey(t *testing.T) {
	fake := newFakeSinauth(t)
	defer fake.close()

	v, err := NewSinauthVerifier(fake.server.URL)
	if err != nil {
		t.Fatalf("NewSinauthVerifier: %v", err)
	}

	// Sign with a different, unpublished key — must not verify against fake's JWKS.
	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "attacker", "role": "admin", "iss": fake.server.URL,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = fake.kid // claims to be the trusted key, but isn't signed with it
	signed, err := token.SignedString(otherPriv)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := v.Verify(context.Background(), signed); err == nil {
		t.Error("Verify should reject a token signed with an unpublished key")
	}
}

func TestSinauthVerifier_MalformedToken(t *testing.T) {
	fake := newFakeSinauth(t)
	defer fake.close()

	v, err := NewSinauthVerifier(fake.server.URL)
	if err != nil {
		t.Fatalf("NewSinauthVerifier: %v", err)
	}

	if _, _, err := v.Verify(context.Background(), "not-a-jwt"); err == nil {
		t.Error("Verify should reject a malformed token")
	}
}
