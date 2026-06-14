package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenType discriminates access vs refresh tokens via the typ claim.
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// IssuerConfig groups Issuer construction options.
type IssuerConfig struct {
	SigningKey []byte // HS256 key — the "primary" rotation slot
	KeyID      string // jwt header kid (optional)
	Issuer     string // iss claim
	Audience   string // aud claim (optional)
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// Issuer mints HS256 access + refresh tokens. Independent of Verifier
// so the issuance signing key is always the primary slot — verifiers
// in the same process accept tokens minted by this Issuer for as long
// as the secret remains in any of the three rotation slots.
type Issuer struct {
	cfg IssuerConfig
	now func() time.Time
}

// NewIssuer constructs an Issuer. SigningKey must be non-empty.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	if len(cfg.SigningKey) == 0 {
		return nil, errors.New("auth: issuer signing key empty")
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 8 * time.Hour
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 7 * 24 * time.Hour
	}
	return &Issuer{cfg: cfg, now: time.Now}, nil
}

// AccessTTL exposes the configured access token lifetime so handlers
// can populate the expires_in field of /auth/login responses.
func (i *Issuer) AccessTTL() time.Duration { return i.cfg.AccessTTL }

// RefreshTTL exposes the configured refresh token lifetime.
func (i *Issuer) RefreshTTL() time.Duration { return i.cfg.RefreshTTL }

// IssueAccessToken mints an HS256 access JWT for the given subject.
// The returned string is the encoded compact-serialisation token.
func (i *Issuer) IssueAccessToken(sub, role, tenantID string) (string, string, error) {
	jti := newJTI()
	now := i.now()
	claims := jwt.MapClaims{
		"sub":       sub,
		"role":      role,
		"tenant_id": tenantID,
		"iss":       i.cfg.Issuer,
		"iat":       now.Unix(),
		"exp":       now.Add(i.cfg.AccessTTL).Unix(),
		"jti":       jti,
		"typ":       TokenTypeAccess,
	}
	if i.cfg.Audience != "" {
		claims["aud"] = i.cfg.Audience
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if i.cfg.KeyID != "" {
		tok.Header["kid"] = i.cfg.KeyID
	}
	signed, err := tok.SignedString(i.cfg.SigningKey)
	if err != nil {
		return "", "", fmt.Errorf("auth: sign access: %w", err)
	}
	return signed, jti, nil
}

// IssueRefreshToken mints a refresh JWT bound to a session ID. The
// returned token is the canonical refresh-token wire value.
func (i *Issuer) IssueRefreshToken(userID, sessionID string) (string, error) {
	now := i.now()
	claims := jwt.MapClaims{
		"sub": userID,
		"sid": sessionID,
		"iss": i.cfg.Issuer,
		"iat": now.Unix(),
		"exp": now.Add(i.cfg.RefreshTTL).Unix(),
		"jti": newJTI(),
		"typ": TokenTypeRefresh,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(i.cfg.SigningKey)
	if err != nil {
		return "", fmt.Errorf("auth: sign refresh: %w", err)
	}
	return signed, nil
}

// ParseRefresh extracts the (subject, sessionID, jti) from a refresh
// token, validating signature, type, and expiry. Issuer mismatch is a
// parse error.
func (i *Issuer) ParseRefresh(token string) (sub, sid, jti string, err error) {
	parsed, perr := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("auth: only HS256 supported")
		}
		return i.cfg.SigningKey, nil
	})
	if perr != nil {
		err = perr
		return
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		err = errors.New("auth: invalid refresh claims")
		return
	}
	if t, _ := mc["typ"].(string); t != TokenTypeRefresh {
		err = errors.New("auth: not a refresh token")
		return
	}
	if iss, _ := mc["iss"].(string); i.cfg.Issuer != "" && iss != i.cfg.Issuer {
		err = errors.New("auth: issuer mismatch")
		return
	}
	sub, _ = mc["sub"].(string)
	sid, _ = mc["sid"].(string)
	jti, _ = mc["jti"].(string)
	if sub == "" || sid == "" {
		err = errors.New("auth: refresh missing sub/sid")
		return
	}
	return
}

// newJTI returns a 128-bit random base64 token identifier.
func newJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to UUIDv4 — also random.
		return uuid.NewString()
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
