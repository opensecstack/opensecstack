package meetings

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Microsoft Bot Framework's fixed OpenID discovery endpoint. The document
// it returns points at the actual (rotatable) JWKS URI and issuer, so this
// is the only hardcoded URL — everything else is fetched dynamically.
// See https://learn.microsoft.com/azure/bot-service/rest-api/bot-framework-rest-connector-authentication
//
// Variable (not const) so tests can point it at an httptest server instead
// of the real Microsoft endpoint.
var teamsOpenIDConfigURL = "https://login.botframework.com/v1/.well-known/openidconfiguration"

// teamsJWKSCacheTTL bounds how long fetched signing keys are trusted before
// a background refresh is attempted. A stale cache still serves known kids
// past this TTL (see teamsKeyCache.getKey) — it never hard-fails a request
// just because the periodic refresh hasn't run yet.
const teamsJWKSCacheTTL = 24 * time.Hour

// openIDConfig is the subset of an OpenID Connect discovery document this
// package needs.
type openIDConfig struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// jwksKey is the subset of a JWK (RFC 7517) this package needs to
// reconstruct an RSA public key.
type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

// teamsKeyCache holds the Bot Framework signing keys fetched from its JWKS
// endpoint, keyed by "kid". Safe for concurrent use.
type teamsKeyCache struct {
	mu        sync.RWMutex
	issuer    string
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	client    *http.Client
}

var teamsKeys = &teamsKeyCache{
	client: &http.Client{Timeout: 10 * time.Second},
}

// getKey returns the RSA public key for kid, fetching (or refreshing) the
// JWKS from Microsoft if the cache is empty, stale, or doesn't contain kid
// yet (covers Microsoft rotating keys between our refreshes).
func (c *teamsKeyCache) getKey(kid string) (*rsa.PublicKey, string, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	issuer := c.issuer
	stale := time.Since(c.fetchedAt) > teamsJWKSCacheTTL
	c.mu.RUnlock()

	if ok && !stale {
		return key, issuer, nil
	}

	if err := c.refresh(); err != nil {
		// A fetch failure with a cached (even if stale) key for this kid is
		// safer than hard-failing every webhook while Microsoft's discovery
		// endpoint is transiently unreachable.
		if ok {
			return key, issuer, nil
		}
		return nil, "", fmt.Errorf("meetings: refreshing Teams JWKS: %w", err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok = c.keys[kid]
	if !ok {
		return nil, "", fmt.Errorf("meetings: no Teams signing key for kid %q", kid)
	}
	return key, c.issuer, nil
}

// refresh fetches the OpenID discovery document, then the JWKS it points
// at, and replaces the cached key set atomically.
func (c *teamsKeyCache) refresh() error {
	cfg, err := c.fetchOpenIDConfig()
	if err != nil {
		return err
	}

	keys, err := c.fetchJWKS(cfg.JWKSURI)
	if err != nil {
		return err
	}

	parsed := make(map[string]*rsa.PublicKey, len(keys))
	for _, k := range keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k)
		if err != nil {
			continue // skip a single malformed key rather than failing the whole refresh
		}
		parsed[k.Kid] = pub
	}
	if len(parsed) == 0 {
		return fmt.Errorf("meetings: Teams JWKS refresh returned zero usable RSA keys")
	}

	c.mu.Lock()
	c.keys = parsed
	c.issuer = cfg.Issuer
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *teamsKeyCache) fetchOpenIDConfig() (*openIDConfig, error) {
	resp, err := c.client.Get(teamsOpenIDConfigURL)
	if err != nil {
		return nil, fmt.Errorf("fetching Bot Framework OpenID config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching Bot Framework OpenID config: status %d", resp.StatusCode)
	}
	var cfg openIDConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decoding Bot Framework OpenID config: %w", err)
	}
	if cfg.JWKSURI == "" || cfg.Issuer == "" {
		return nil, fmt.Errorf("missing issuer/jwks_uri in Bot Framework OpenID config")
	}
	return &cfg, nil
}

func (c *teamsKeyCache) fetchJWKS(jwksURI string) ([]jwksKey, error) {
	resp, err := c.client.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetching Bot Framework JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching Bot Framework JWKS: status %d", resp.StatusCode)
	}
	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decoding Bot Framework JWKS: %w", err)
	}
	return jwks.Keys, nil
}

// rsaPublicKeyFromJWK reconstructs an *rsa.PublicKey from a JWK's base64url
// "n" (modulus) and "e" (exponent) fields per RFC 7518 §6.3.1.
func rsaPublicKeyFromJWK(k jwksKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding JWK modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding JWK exponent: %w", err)
	}

	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("JWK exponent decoded to zero")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}

// validateTeamsToken validates the Bearer JWT Azure's Bot Framework
// connector attaches to every Activity POST, per
// https://learn.microsoft.com/azure/bot-service/rest-api/bot-framework-rest-connector-authentication:
// RS256 signature against Microsoft's published JWKS, issuer pinned to
// api.botframework.com, and audience equal to this bot's Azure AD
// application (client) ID.
//
// audience is the bot's Microsoft App ID (PlatformConfig.ClientID for
// PlatformTeams) — the token's "aud" claim must equal it exactly.
func validateTeamsToken(audience string, headers http.Header) bool {
	if audience == "" {
		return false
	}

	authz := headers.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		return false
	}
	raw := strings.TrimSpace(strings.TrimPrefix(authz, prefix))
	if raw == "" {
		return false
	}

	keyfunc := func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("token header missing kid")
		}
		key, _, err := teamsKeys.getKey(kid)
		return key, err
	}

	token, err := jwt.Parse(raw, keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithAudience(audience),
		jwt.WithIssuer("https://api.botframework.com"),
		jwt.WithLeeway(2*time.Minute),
	)
	return err == nil && token.Valid
}
