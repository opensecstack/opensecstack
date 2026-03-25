package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// TokenType indicates the type of authentication mechanism.
type TokenType string

const (
	TokenTypeBearer TokenType = "bearer"
	TokenTypeJWT    TokenType = "jwt"
	TokenTypeOAuth2 TokenType = "oauth2"
	TokenTypeAPIKey TokenType = "apikey"
	TokenTypeBasic  TokenType = "basic"
)

// Config holds authentication configuration for a scan.
type Config struct {
	Type       TokenType
	Token      string // Bearer / JWT / OAuth2 token
	APIKey     string
	APIKeyName string // Header or query param name
	APIKeyIn   string // "header" or "query"
	Username   string
	Password   string
	// OtherTokens holds additional tokens for cross-user BOLA tests.
	OtherTokens []string
}

// Handler manages token lifecycle for a scan.
// It is safe for concurrent use.
type Handler struct {
	mu     sync.RWMutex
	config Config
	secret []byte // HMAC secret for generating test JWTs (if not provided externally)
}

// NewHandler creates a new Handler from the provided config.
// If secret is nil and JWT generation is needed, a random 32-byte secret is generated.
func NewHandler(cfg Config, secret []byte) (*Handler, error) {
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("generate handler secret: %w", err)
		}
	}
	return &Handler{config: cfg, secret: secret}, nil
}

// GetConfig returns the current authentication configuration.
func (h *Handler) GetConfig() Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.config
}

// UpdateToken replaces the current token. Useful for OAuth2 refresh flows.
func (h *Handler) UpdateToken(token string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.config.Token = token
}

// Headers returns the authentication headers for a normal (valid) request.
func (h *Handler) Headers() map[string]string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.buildHeaders(&h.config)
}

// buildHeaders constructs auth headers from a config.
func (h *Handler) buildHeaders(cfg *Config) map[string]string {
	headers := make(map[string]string)
	switch cfg.Type {
	case TokenTypeBearer, TokenTypeJWT, TokenTypeOAuth2:
		if cfg.Token != "" {
			headers["Authorization"] = "Bearer " + cfg.Token
		}
	case TokenTypeAPIKey:
		if cfg.APIKey != "" && strings.ToLower(cfg.APIKeyIn) == "header" {
			name := cfg.APIKeyName
			if name == "" {
				name = "X-API-Key"
			}
			headers[name] = cfg.APIKey
		}
	case TokenTypeBasic:
		if cfg.Username != "" {
			creds := cfg.Username + ":" + cfg.Password
			encoded := base64.StdEncoding.EncodeToString([]byte(creds))
			headers["Authorization"] = "Basic " + encoded
		}
	}
	return headers
}

// GenerateExpiredToken returns a JWT whose exp claim is set to Unix epoch 1 (always expired).
// The token is signed with the handler's secret so it has a valid signature format,
// but the expiry ensures it should be rejected by a correctly implemented server.
func (h *Handler) GenerateExpiredToken() (string, error) {
	h.mu.RLock()
	secret := h.secret
	h.mu.RUnlock()

	payload := jwtPayload{
		Sub: "apiguard-expiry-test",
		Iat: 1,
		Exp: 1, // Unix epoch — always expired
		Nbf: 1,
	}
	return signJWT(payload, secret)
}

// GenerateOtherUserToken returns a JWT for a different subject than the configured token.
// Used in BOLA cross-user tests.
func (h *Handler) GenerateOtherUserToken(otherUserID string) (string, error) {
	h.mu.RLock()
	secret := h.secret
	h.mu.RUnlock()

	if otherUserID == "" {
		otherUserID = "apiguard-other-user-" + randomSuffix()
	}

	now := time.Now()
	payload := jwtPayload{
		Sub: otherUserID,
		Iat: now.Unix(),
		Exp: now.Add(1 * time.Hour).Unix(),
		Nbf: now.Unix(),
	}
	return signJWT(payload, secret)
}

// GenerateInvalidToken returns a token string that is syntactically invalid.
// Any correct JWT validation implementation must reject this.
func (h *Handler) GenerateInvalidToken() string {
	return "invalid.garbage.apiguard-test." + randomSuffix()
}

// GenerateNoAuthConfig returns an auth config with no credentials.
// Used to test endpoints that should require authentication.
func (h *Handler) GenerateNoAuthConfig() *Config {
	return &Config{}
}

// --- JWT helpers ---

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtPayload struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Nbf int64  `json:"nbf"`
}

// signJWT creates a HS256 JWT signed with the provided secret.
func signJWT(payload jwtPayload, secret []byte) (string, error) {
	headerBytes, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal jwt payload: %w", err)
	}

	h := base64.RawURLEncoding.EncodeToString(headerBytes)
	p := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := h + "." + p

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// randomSuffix returns a short random hex string for use in test identifiers.
func randomSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "0000"
	}
	return fmt.Sprintf("%x", b)
}
