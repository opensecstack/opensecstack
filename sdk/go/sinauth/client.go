package sinauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Client verifies sinauth-issued RS256 JWT tokens.
type Client struct {
	issuer     string
	httpClient *http.Client
	mu         sync.RWMutex
	keys       map[string]*rsa.PublicKey // kid → key
	keysExp    time.Time
}

// Claims holds the parsed sinauth JWT claims.
type Claims struct {
	Sub         string   `json:"sub"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scope"`
	Role        string   `json:"role"`
	ClientRoles []string `json:"client_roles"`
	Issuer      string   `json:"iss"`
	Audience    []string `json:"aud"`
	ExpiresAt   int64    `json:"exp"`
	IssuedAt    int64    `json:"iat"`
	JWTID       string   `json:"jti"`
}

// GetExpirationTime implements jwt.Claims.
func (c Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt implements jwt.Claims.
func (c Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetNotBefore implements jwt.Claims.
func (c Claims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetIssuer implements jwt.Claims.
func (c Claims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements jwt.Claims.
func (c Claims) GetSubject() (string, error) {
	return c.Sub, nil
}

// GetAudience implements jwt.Claims.
func (c Claims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings(c.Audience), nil
}

// UserInfo holds the OIDC userinfo response.
type UserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

type discoveryDoc struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// New creates a new Client by fetching the OIDC discovery document from the
// given issuerURL (e.g. "https://auth.sin.to"). Returns an error if the
// discovery document cannot be fetched or the issuer does not match.
func New(issuerURL string) (*Client, error) {
	issuerURL = strings.TrimRight(issuerURL, "/")

	httpClient := &http.Client{Timeout: 30 * time.Second}

	discURL := issuerURL + "/.well-known/openid-configuration"
	resp, err := httpClient.Get(discURL)
	if err != nil {
		return nil, fmt.Errorf("sinauth: fetching discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sinauth: discovery document returned status %d", resp.StatusCode)
	}

	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("sinauth: decoding discovery document: %w", err)
	}

	docIssuer := strings.TrimRight(doc.Issuer, "/")
	if docIssuer != issuerURL {
		return nil, fmt.Errorf("sinauth: issuer mismatch: got %q, want %q", doc.Issuer, issuerURL)
	}

	return &Client{
		issuer:     issuerURL,
		httpClient: httpClient,
		keys:       make(map[string]*rsa.PublicKey),
	}, nil
}

// VerifyToken parses and validates a sinauth-issued JWT token string.
// It refreshes the JWKS key cache as needed (keys are cached for 5 minutes).
func (c *Client) VerifyToken(ctx context.Context, tokenString string) (*Claims, error) {
	// Parse the header to get the kid before full verification.
	kid, err := extractKID(tokenString)
	if err != nil {
		return nil, fmt.Errorf("sinauth: extracting kid: %w", err)
	}

	key, err := c.getKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("sinauth: getting public key: %w", err)
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("sinauth: unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuedAt())
	if err != nil {
		return nil, fmt.Errorf("sinauth: parsing token: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("sinauth: token is not valid")
	}

	// Validate issuer.
	if strings.TrimRight(claims.Issuer, "/") != c.issuer {
		return nil, fmt.Errorf("sinauth: issuer mismatch: got %q, want %q", claims.Issuer, c.issuer)
	}

	return claims, nil
}

// VerifyTokenForClient verifies the token and additionally checks that the
// token belongs to the specified clientID (either as client_id claim or in
// the audience list).
func (c *Client) VerifyTokenForClient(ctx context.Context, tokenString, clientID string) (*Claims, error) {
	claims, err := c.VerifyToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	if claims.ClientID == clientID {
		return claims, nil
	}
	for _, aud := range claims.Audience {
		if aud == clientID {
			return claims, nil
		}
	}

	return nil, fmt.Errorf("sinauth: token not issued for client %q", clientID)
}

// FetchUserInfo fetches user information from the sinauth userinfo endpoint
// using the provided access token.
func (c *Client) FetchUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuer+"/oauth/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("sinauth: creating userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sinauth: fetching userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sinauth: userinfo returned status %d", resp.StatusCode)
	}

	var info UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("sinauth: decoding userinfo: %w", err)
	}
	return &info, nil
}

// refreshKeys fetches the JWKS from the issuer and updates the key cache.
// The caller must hold c.mu (write lock is acquired inside).
func (c *Client) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuer+"/.well-known/jwks.json", nil)
	if err != nil {
		return fmt.Errorf("sinauth: creating JWKS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sinauth: fetching JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sinauth: JWKS returned status %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("sinauth: decoding JWKS: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := jwkToRSA(k)
		if err != nil {
			return fmt.Errorf("sinauth: parsing JWK kid=%q: %w", k.Kid, err)
		}
		newKeys[k.Kid] = pub
	}

	c.mu.Lock()
	c.keys = newKeys
	c.keysExp = time.Now().Add(5 * time.Minute)
	c.mu.Unlock()

	return nil
}

// getKey returns the RSA public key for the given kid, refreshing the cache
// if it has expired or the key is not found.
func (c *Client) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	expired := time.Now().After(c.keysExp)
	c.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	// Refresh and retry.
	if err := c.refreshKeys(ctx); err != nil {
		return nil, err
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("sinauth: key not found: %s", kid)
	}
	return key, nil
}

// extractKID parses the JWT header (without verifying the signature) and
// returns the "kid" field.
func extractKID(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed JWT: expected 3 parts")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decoding JWT header: %w", err)
	}

	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("parsing JWT header: %w", err)
	}
	if header.Kid == "" {
		return "", errors.New("JWT header missing kid")
	}
	return header.Kid, nil
}

// jwkToRSA converts a JWK into an *rsa.PublicKey.
func jwkToRSA(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
