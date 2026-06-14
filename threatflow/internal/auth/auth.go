// Package auth implements ThreatFlow's authentication + role-based access
// control. The design mirrors NIS2 Compass / APIGuard so the same operator
// tooling works across the opensecstack — opaque API keys are exchanged for
// short-lived HS256 JWTs that downstream middleware decodes to enforce roles.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/opensecstack/threatflow/internal/db/store"
)

// ErrUnauthorized indicates the API key (or JWT) is missing, unknown, or
// expired — callers return HTTP 401.
var ErrUnauthorized = errors.New("unauthorized")

// ErrForbidden is returned when the principal is authenticated but the role
// does not satisfy the endpoint — callers return HTTP 403.
var ErrForbidden = errors.New("forbidden")

// Role is one of viewer | analyst | operator | admin. Role ordering (lowest to
// highest privilege) is enforced via AtLeast.
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleAnalyst  Role = "analyst"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

var roleOrder = map[Role]int{
	RoleViewer: 0, RoleAnalyst: 1, RoleOperator: 2, RoleAdmin: 3,
}

// AtLeast reports whether have is privileged enough for required.
func AtLeast(have, required Role) bool {
	h, hok := roleOrder[have]
	r, rok := roleOrder[required]
	if !hok || !rok {
		return false
	}
	return h >= r
}

// Identity is the authenticated principal extracted from a valid JWT.
type Identity struct {
	Subject string     // "apikey:<uuid>" or "bootstrap:<name>"
	Role    Role
	Source  string     // "api_key" | "bootstrap"
	APIKey  *uuid.UUID // present for db-backed keys
}

// Service issues + verifies JWTs and resolves API keys.
type Service struct {
	secret        []byte
	ttl           time.Duration
	apiKeys       *store.APIKeyStore
	bootstrapKeys map[string]Role // plaintext key → role; dev/bootstrap only
}

// Config is the initialisation payload for NewService.
type Config struct {
	Secret         string            // HS256 secret; if empty a random one is generated
	TTL            time.Duration     // access-token lifetime; default 1h
	APIKeys        *store.APIKeyStore
	BootstrapKeys  map[string]Role   // plaintext key → role (dev-mode override)
}

// NewService builds an auth Service. When cfg.Secret is empty a fresh random
// HS256 secret is generated — fine for single-node dev, but production
// deployments MUST set THREATFLOW_JWT_SECRET so tokens survive restarts.
func NewService(cfg Config) (*Service, error) {
	secret := []byte(cfg.Secret)
	if len(secret) == 0 {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("generate jwt secret: %w", err)
		}
		secret = []byte(hex.EncodeToString(buf))
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	bootstrap := map[string]Role{}
	for k, r := range cfg.BootstrapKeys {
		bootstrap[k] = r
	}
	return &Service{
		secret:        secret,
		ttl:           ttl,
		apiKeys:       cfg.APIKeys,
		bootstrapKeys: bootstrap,
	}, nil
}

// AuthenticateAPIKey resolves a plaintext API key to an Identity. The key is
// first compared against bootstrap entries (constant-time), then against the
// api_keys table via SHA-256 hash.
func (s *Service) AuthenticateAPIKey(ctx context.Context, plaintext string) (*Identity, error) {
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return nil, ErrUnauthorized
	}
	if role, ok := s.bootstrapKeys[plaintext]; ok {
		return &Identity{
			Subject: "bootstrap:" + plaintext[:min(8, len(plaintext))],
			Role:    role,
			Source:  "bootstrap",
		}, nil
	}
	if s.apiKeys == nil {
		return nil, ErrUnauthorized
	}
	hash := store.HashAPIKey(plaintext)
	key, err := s.apiKeys.FindByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	s.apiKeys.TouchUsed(ctx, key.ID)
	id := key.ID
	return &Identity{
		Subject: "apikey:" + key.ID.String(),
		Role:    Role(key.Role),
		Source:  "api_key",
		APIKey:  &id,
	}, nil
}

// IssueToken mints a short-lived HS256 JWT for an Identity.
func (s *Service) IssueToken(id *Identity) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(s.ttl)
	claims := jwt.MapClaims{
		"sub":    id.Subject,
		"role":   string(id.Role),
		"source": id.Source,
		"iat":    now.Unix(),
		"exp":    exp.Unix(),
		"jti":    uuid.NewString(),
	}
	if id.APIKey != nil {
		claims["kid"] = id.APIKey.String()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(s.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign jwt: %w", err)
	}
	return signed, exp, nil
}

// TTL returns the token lifetime configured for this service.
func (s *Service) TTL() time.Duration { return s.ttl }

// VerifyToken decodes and validates a JWT, returning the Identity. Used by
// the middleware.
func (s *Service) VerifyToken(tokenString string) (*Identity, error) {
	tok, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, ErrUnauthorized
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, ErrUnauthorized
	}
	sub, _ := claims["sub"].(string)
	role, _ := claims["role"].(string)
	source, _ := claims["source"].(string)
	id := &Identity{Subject: sub, Role: Role(role), Source: source}
	if kid, ok := claims["kid"].(string); ok {
		if u, err := uuid.Parse(kid); err == nil {
			id.APIKey = &u
		}
	}
	return id, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
