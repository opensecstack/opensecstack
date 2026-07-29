package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/opensecstack/sdk/go/sinauth"
	"github.com/rs/zerolog/log"
)

// errInvalidTokenType is returned by validateJWT when the typ claim is not "access".
var errInvalidTokenType = fmt.Errorf("invalid token type")

// claimsKey is the context key for storing JWT claims.
type claimsKey struct{}

// Claims represents the parsed JWT payload claims.
type Claims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Nbf int64  `json:"nbf,omitempty"`
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Typ string `json:"typ"`
}

// ClaimsFromContext retrieves the JWT claims from the request context.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*Claims)
	return c, ok
}

// ContextWithClaims returns a copy of ctx carrying the given Claims, exactly
// as the JWT middleware would store them after successful authentication.
// Exported so handler-level tests (and any code composing requests outside
// the normal HTTP middleware chain) can simulate an authenticated caller
// without duplicating the unexported claimsKey.
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, c)
}

// JWTAuth returns a middleware that validates JWT tokens in the Authorization header.
// trustedProxies is used to correctly resolve the real client IP for log entries
// (X-Forwarded-For is honoured only when the direct peer is a trusted proxy).
// Pass nil to always use r.RemoteAddr.
//
// Secret rotation: if previousSecret is non-empty and validation with secret
// fails due to a signature error, the middleware retries with previousSecret.
// This allows zero-downtime rotation: set previousSecret to the old key and
// secret to the new key; tokens issued under the old key remain valid until
// they expire naturally. Once all old tokens have expired, clear previousSecret.
func JWTAuth(secret string, trustedProxies []*net.IPNet) func(next http.Handler) http.Handler {
	return JWTAuthWithRotation(secret, "", trustedProxies)
}

// JWTAuthWithRotation is like JWTAuth but also accepts tokens signed with
// previousSecret when it is non-empty. Use this during JWT secret rotation.
func JWTAuthWithRotation(secret, previousSecret string, trustedProxies []*net.IPNet) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If no secret is configured, reject all requests to protected endpoints.
			// A JWT secret must be configured for the server to authenticate requests.
			if secret == "" {
				unauthorized(w, "authentication is not configured: JWT secret is missing")
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				unauthorized(w, "missing Authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				unauthorized(w, "invalid Authorization header format")
				return
			}

			token := parts[1]
			if token == "" {
				unauthorized(w, "empty bearer token")
				return
			}

			// Validate JWT token signature and claims using the current secret.
			claims, err := validateJWT(token, secret)
			if err != nil && previousSecret != "" {
				// Secret rotation: if signature verification failed and a previous
				// secret is configured, retry validation with the previous secret.
				// This allows tokens issued before the rotation to remain valid.
				if prevClaims, prevErr := validateJWT(token, previousSecret); prevErr == nil {
					claims = prevClaims
					err = nil
				}
			}
			if err != nil {
				// A-M1: use the real client IP (honoring trusted proxies) rather
				// than the raw r.RemoteAddr which may be a proxy address.
				clientIP := ClientIPFromRequest(r, trustedProxies)
				log.Warn().Err(err).Str("client_ip", clientIP).Msg("JWT validation failed")
				if err == errInvalidTokenType {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "invalid token type",
						"code":  "INVALID_TOKEN",
					})
					return
				}
				unauthorized(w, "invalid or expired token")
				return
			}

			// Store claims in context for downstream handlers.
			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// JWTAuthWithProvider reads secrets dynamically from a SecretProvider on every
// request, enabling zero-downtime rotation via SecretProvider.Rotate() without
// restarting the server. It tries each secret returned by sp.All() in order
// and accepts the token if any one of them validates successfully.
func JWTAuthWithProvider(sp *SecretProvider, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return JWTAuthWithProviderAndDenylist(sp, nil, trustedProxies)
}

// JWTAuthWithProviderAndDenylist is like JWTAuthWithProvider but also checks
// the supplied TokenDenylist on every request. Tokens whose SHA-256 hash
// appears in the denylist are rejected with 401 even when the signature and
// expiry are otherwise valid. Pass nil for denylist to skip the check.
func JWTAuthWithProviderAndDenylist(sp *SecretProvider, denylist *TokenDenylist, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			current := sp.Current()
			if len(current) == 0 {
				unauthorized(w, "authentication is not configured: JWT secret is missing")
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				unauthorized(w, "missing Authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				unauthorized(w, "invalid Authorization header format")
				return
			}

			token := parts[1]
			if token == "" {
				unauthorized(w, "empty bearer token")
				return
			}

			// Denylist check: reject tokens that have been explicitly logged out
			// before their natural expiry. Checked before signature validation so
			// a logged-out token is never treated as valid even briefly.
			if denylist != nil && denylist.IsDenied(HashToken(token)) {
				clientIP := ClientIPFromRequest(r, trustedProxies)
				log.Warn().Str("client_ip", clientIP).Msg("denied access token presented")
				unauthorized(w, "token has been revoked")
				return
			}

			// Try each secret in order: index 0 is the active signing key,
			// subsequent entries are grace-period verification-only keys.
			var (
				claims *Claims
				err    error
			)
			for _, secret := range sp.All() {
				claims, err = validateJWT(token, string(secret))
				if err == nil {
					break
				}
			}

			if err != nil {
				clientIP := ClientIPFromRequest(r, trustedProxies)
				log.Warn().Err(err).Str("client_ip", clientIP).Msg("JWT validation failed")
				if err == errInvalidTokenType {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "invalid token type",
						"code":  "INVALID_TOKEN",
					})
					return
				}
				unauthorized(w, "invalid or expired token")
				return
			}

			// Store claims in context for downstream handlers.
			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// isRS256Token returns true when the JWT header contains "alg":"RS256".
// It does not verify the token; it only inspects the header segment.
func isRS256Token(tokenString string) bool {
	parts := strings.SplitN(tokenString, ".", 3)
	if len(parts) != 3 {
		return false
	}
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	return header.Alg == "RS256"
}

// sinauthClaimsToLocal converts a sinauth.Claims into the apiguard Claims
// struct so that the rest of the middleware/handler chain sees a uniform type.
// Exp is taken directly from the sinauth token; Iss is set to "sinauth";
// Typ is set to "access" so type-checking middleware stays satisfied.
func sinauthClaimsToLocal(sc *sinauth.Claims) *Claims {
	return &Claims{
		Sub: sc.Sub,
		Exp: sc.ExpiresAt,
		Iat: sc.IssuedAt,
		Iss: "sinauth",
		Typ: "access",
	}
}

// JWTAuthWithSinauth returns a middleware with RS256/HS256 dual-mode auth.
// When sinauthURL is non-empty, a sinauth client is created at call time and
// tokens with alg=RS256 are verified via the sinauth SDK. HS256 tokens
// continue through the existing HMAC path. This is intended for use during
// server initialisation where the sinauth client is created once and reused.
func JWTAuthWithSinauth(secret, sinauthURL string, trustedProxies []*net.IPNet) func(next http.Handler) http.Handler {
	return JWTAuthWithRotationAndSinauth(secret, "", sinauthURL, trustedProxies)
}

// JWTAuthWithRotationAndSinauth is like JWTAuthWithRotation but also accepts
// RS256 tokens issued by sinauth when sinauthURL is non-empty.
func JWTAuthWithRotationAndSinauth(secret, previousSecret, sinauthURL string, trustedProxies []*net.IPNet) func(next http.Handler) http.Handler {
	var sc *sinauth.Client
	if sinauthURL != "" {
		var err error
		sc, err = sinauth.New(sinauthURL)
		if err != nil {
			log.Warn().Err(err).Str("sinauth_url", sinauthURL).Msg("sinauth client init failed; RS256 tokens will be rejected")
		}
	}
	return jwtAuthWithSinauthClient(secret, previousSecret, sc, trustedProxies)
}

// JWTAuthWithProviderDenylistAndSinauth is the full-featured variant that
// combines SecretProvider-based rotation, an access-token denylist, and
// sinauth RS256 verification. Pass nil for sc to disable the RS256 path.
func JWTAuthWithProviderDenylistAndSinauth(sp *SecretProvider, denylist *TokenDenylist, sc *sinauth.Client, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			current := sp.Current()
			if len(current) == 0 && sc == nil {
				unauthorized(w, "authentication is not configured: JWT secret is missing")
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				unauthorized(w, "missing Authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				unauthorized(w, "invalid Authorization header format")
				return
			}

			token := parts[1]
			if token == "" {
				unauthorized(w, "empty bearer token")
				return
			}

			// Denylist check applies regardless of token algorithm.
			if denylist != nil && denylist.IsDenied(HashToken(token)) {
				clientIP := ClientIPFromRequest(r, trustedProxies)
				log.Warn().Str("client_ip", clientIP).Msg("denied access token presented")
				unauthorized(w, "token has been revoked")
				return
			}

			// RS256 path: delegate to sinauth SDK.
			if sc != nil && isRS256Token(token) {
				saClaims, err := sc.VerifyToken(r.Context(), token)
				if err != nil {
					clientIP := ClientIPFromRequest(r, trustedProxies)
					log.Warn().Err(err).Str("client_ip", clientIP).Msg("sinauth RS256 token verification failed")
					unauthorized(w, "invalid or expired token")
					return
				}
				claims := sinauthClaimsToLocal(saClaims)
				ctx := context.WithValue(r.Context(), claimsKey{}, claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// HS256 path: try each secret from the provider in order.
			if len(current) == 0 {
				unauthorized(w, "authentication is not configured: JWT secret is missing")
				return
			}
			var (
				claims *Claims
				err    error
			)
			for _, secret := range sp.All() {
				claims, err = validateJWT(token, string(secret))
				if err == nil {
					break
				}
			}

			if err != nil {
				clientIP := ClientIPFromRequest(r, trustedProxies)
				log.Warn().Err(err).Str("client_ip", clientIP).Msg("JWT validation failed")
				if err == errInvalidTokenType {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "invalid token type",
						"code":  "INVALID_TOKEN",
					})
					return
				}
				unauthorized(w, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// jwtAuthWithSinauthClient is the internal implementation shared by
// JWTAuthWithSinauth and JWTAuthWithRotationAndSinauth.
func jwtAuthWithSinauthClient(secret, previousSecret string, sc *sinauth.Client, trustedProxies []*net.IPNet) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret == "" && sc == nil {
				unauthorized(w, "authentication is not configured: JWT secret is missing")
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				unauthorized(w, "missing Authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				unauthorized(w, "invalid Authorization header format")
				return
			}

			token := parts[1]
			if token == "" {
				unauthorized(w, "empty bearer token")
				return
			}

			// RS256 path.
			if sc != nil && isRS256Token(token) {
				saClaims, err := sc.VerifyToken(r.Context(), token)
				if err != nil {
					clientIP := ClientIPFromRequest(r, trustedProxies)
					log.Warn().Err(err).Str("client_ip", clientIP).Msg("sinauth RS256 token verification failed")
					unauthorized(w, "invalid or expired token")
					return
				}
				claims := sinauthClaimsToLocal(saClaims)
				ctx := context.WithValue(r.Context(), claimsKey{}, claims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// HS256 path.
			if secret == "" {
				unauthorized(w, "authentication is not configured: JWT secret is missing")
				return
			}
			claims, err := validateJWT(token, secret)
			if err != nil && previousSecret != "" {
				if prevClaims, prevErr := validateJWT(token, previousSecret); prevErr == nil {
					claims = prevClaims
					err = nil
				}
			}
			if err != nil {
				clientIP := ClientIPFromRequest(r, trustedProxies)
				log.Warn().Err(err).Str("client_ip", clientIP).Msg("JWT validation failed")
				if err == errInvalidTokenType {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error": "invalid token type",
						"code":  "INVALID_TOKEN",
					})
					return
				}
				unauthorized(w, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ValidateAccessToken is the exported form of validateJWT. It is intended for
// use by handlers that need to inspect an access token without going through
// the full HTTP middleware chain (e.g. the Logout handler).
func ValidateAccessToken(token, secret string) (*Claims, error) {
	return validateJWT(token, secret)
}

// validateJWT performs HMAC-SHA256 JWT validation and returns the parsed claims.
func validateJWT(token, secret string) (*Claims, error) {
	// Split token into header.payload.signature.
	segments := strings.SplitN(token, ".", 3)
	if len(segments) != 3 {
		return nil, fmt.Errorf("token must have 3 parts, got %d", len(segments))
	}

	headerB64, payloadB64, signatureB64 := segments[0], segments[1], segments[2]

	// Decode header to verify algorithm.
	headerBytes, err := base64URLDecode(headerB64)
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid header JSON: %w", err)
	}
	if header.Alg != "HS256" {
		return nil, fmt.Errorf("unsupported algorithm %q, expected HS256", header.Alg)
	}

	// Verify HMAC-SHA256 signature.
	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	actualSig, err := base64URLDecode(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Decode and parse payload claims.
	payloadBytes, err := base64URLDecode(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid payload JSON: %w", err)
	}

	now := time.Now().Unix()

	// Check expiration claim.
	if claims.Exp == 0 {
		return nil, fmt.Errorf("missing exp claim")
	}
	if now > claims.Exp {
		return nil, fmt.Errorf("token has expired")
	}

	// Check issued-at claim (reject tokens issued in the future).
	if claims.Iat > 0 && claims.Iat > now+60 {
		// Allow 60 seconds of clock skew.
		return nil, fmt.Errorf("token issued in the future")
	}

	// Check not-before claim (with 60 second clock skew tolerance).
	if claims.Nbf > 0 && now < claims.Nbf-60 {
		return nil, fmt.Errorf("token is not yet valid")
	}

	if claims.Sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}
	if claims.Iss != "apiguard" {
		return nil, fmt.Errorf("invalid iss claim: %q", claims.Iss)
	}
	if claims.Aud != "apiguard" {
		return nil, fmt.Errorf("invalid aud claim: %q", claims.Aud)
	}
	if claims.Typ != "access" {
		return nil, errInvalidTokenType
	}

	return &claims, nil
}

// base64URLDecode decodes a base64url-encoded string (without padding).
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthorized",
		"message": message,
	})
}
