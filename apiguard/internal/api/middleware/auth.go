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

// JWTAuth returns a middleware that validates JWT tokens in the Authorization header.
// trustedProxies is used to correctly resolve the real client IP for log entries
// (X-Forwarded-For is honoured only when the direct peer is a trusted proxy).
// Pass nil to always use r.RemoteAddr.
func JWTAuth(secret string, trustedProxies []*net.IPNet) func(next http.Handler) http.Handler {
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

			// Validate JWT token signature and claims.
			claims, err := validateJWT(token, secret)
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
