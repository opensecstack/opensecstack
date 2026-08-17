package meetings

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

// newTestBotFrameworkServer stands up a fake Bot Framework discovery +
// JWKS endpoint backed by a freshly generated RSA key, and returns the
// server plus a signer function for minting test tokens with that key.
func newTestBotFrameworkServer(t *testing.T) (*httptest.Server, *rsa.PrivateKey, string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test RSA key: %v", err)
	}
	const kid = "test-kid-1"

	mux := http.NewServeMux()
	var srv *httptest.Server // captured by closure for jwks_uri below

	mux.HandleFunc("/.well-known/openidconfiguration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(openIDConfig{
			Issuer:  "https://api.botframework.com",
			JWKSURI: srv.URL + "/.well-known/keys",
		})
	})
	mux.HandleFunc("/.well-known/keys", func(w http.ResponseWriter, r *http.Request) {
		nBytes := priv.N.Bytes()
		eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
		_ = json.NewEncoder(w).Encode(jwksResponse{Keys: []jwksKey{{
			Kty: "RSA",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(nBytes),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		}}})
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv, priv, kid
}

// signTestToken mints an RS256 JWT with the given claims, signed by priv
// and tagged with kid — mirroring the shape of a real Bot Framework token.
func signTestToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("signing test token: %v", err)
	}
	return signed
}

// resetTeamsKeyCache points the package-level cache at a fresh, empty
// instance so each test starts from a clean slate regardless of test order.
func resetTeamsKeyCache(t *testing.T) {
	t.Helper()
	prev := teamsKeys
	teamsKeys = &teamsKeyCache{client: &http.Client{Timeout: 5 * time.Second}}
	t.Cleanup(func() { teamsKeys = prev })
}

func TestValidateTeamsToken_Valid(t *testing.T) {
	srv, priv, kid := newTestBotFrameworkServer(t)
	resetTeamsKeyCache(t)
	teamsOpenIDConfigURL = srv.URL + "/.well-known/openidconfiguration"

	const audience = "test-bot-app-id"
	token := signTestToken(t, priv, kid, jwt.MapClaims{
		"iss": "https://api.botframework.com",
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(),
	})

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)

	if !validateTeamsToken(audience, headers) {
		t.Fatal("expected a validly-signed, correctly-claimed token to pass")
	}
}

func TestValidateTeamsToken_WrongAudience(t *testing.T) {
	srv, priv, kid := newTestBotFrameworkServer(t)
	resetTeamsKeyCache(t)
	teamsOpenIDConfigURL = srv.URL + "/.well-known/openidconfiguration"

	token := signTestToken(t, priv, kid, jwt.MapClaims{
		"iss": "https://api.botframework.com",
		"aud": "someone-elses-bot-app-id",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)

	if validateTeamsToken("test-bot-app-id", headers) {
		t.Fatal("expected a token minted for a different audience to be rejected")
	}
}

func TestValidateTeamsToken_WrongIssuer(t *testing.T) {
	srv, priv, kid := newTestBotFrameworkServer(t)
	resetTeamsKeyCache(t)
	teamsOpenIDConfigURL = srv.URL + "/.well-known/openidconfiguration"

	const audience = "test-bot-app-id"
	token := signTestToken(t, priv, kid, jwt.MapClaims{
		"iss": "https://evil.example.com",
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)

	if validateTeamsToken(audience, headers) {
		t.Fatal("expected a token with the wrong issuer to be rejected")
	}
}

func TestValidateTeamsToken_Expired(t *testing.T) {
	srv, priv, kid := newTestBotFrameworkServer(t)
	resetTeamsKeyCache(t)
	teamsOpenIDConfigURL = srv.URL + "/.well-known/openidconfiguration"

	const audience = "test-bot-app-id"
	token := signTestToken(t, priv, kid, jwt.MapClaims{
		"iss": "https://api.botframework.com",
		"aud": audience,
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)

	if validateTeamsToken(audience, headers) {
		t.Fatal("expected an expired token to be rejected")
	}
}

func TestValidateTeamsToken_WrongSigningKey(t *testing.T) {
	srv, _, kid := newTestBotFrameworkServer(t)
	resetTeamsKeyCache(t)
	teamsOpenIDConfigURL = srv.URL + "/.well-known/openidconfiguration"

	// Sign with a DIFFERENT key than the one the fake JWKS endpoint serves —
	// simulates a forged token.
	forgedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating forged key: %v", err)
	}
	const audience = "test-bot-app-id"
	token := signTestToken(t, forgedKey, kid, jwt.MapClaims{
		"iss": "https://api.botframework.com",
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)

	if validateTeamsToken(audience, headers) {
		t.Fatal("expected a token signed by an untrusted key to be rejected")
	}
}

func TestValidateTeamsToken_MissingAuthHeader(t *testing.T) {
	resetTeamsKeyCache(t)
	headers := http.Header{}
	if validateTeamsToken("test-bot-app-id", headers) {
		t.Fatal("expected no Authorization header to be rejected")
	}
}

func TestValidateTeamsToken_MalformedAuthHeader(t *testing.T) {
	resetTeamsKeyCache(t)
	headers := http.Header{}
	headers.Set("Authorization", "not-a-bearer-token")
	if validateTeamsToken("test-bot-app-id", headers) {
		t.Fatal("expected a non-Bearer Authorization header to be rejected")
	}
}

func TestValidateTeamsToken_EmptyAudienceConfigured(t *testing.T) {
	resetTeamsKeyCache(t)
	headers := http.Header{}
	headers.Set("Authorization", "Bearer some.token.value")
	if validateTeamsToken("", headers) {
		t.Fatal("expected validation to fail closed when no audience is configured")
	}
}

func TestValidateSignature_TeamsDispatches(t *testing.T) {
	// ValidateSignature must route PlatformTeams through the real JWT
	// validator, not the old always-true stub.
	resetTeamsKeyCache(t)
	headers := http.Header{}
	headers.Set("Authorization", "Bearer garbage")
	if ValidateSignature(PlatformTeams, "test-bot-app-id", nil, headers) {
		t.Fatal("expected ValidateSignature(PlatformTeams, ...) to reject a garbage token, not stub-return true")
	}
}
