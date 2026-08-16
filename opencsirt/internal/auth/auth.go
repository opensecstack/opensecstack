// Package auth implements JWT (HS256/RS256) authentication and role-based
// authorization for OpenCSIRT.
//
// Roles (most → least privileged):
//
//	admin · csirt_lead · operator · analyst · external_peer · viewer
//
// `csirt_lead` may publish advisories and escalate to peers.
// `external_peer` may only read advisories tagged TLP:CLEAR/GREEN
// and submit IOC bundles back to OpenCSIRT (federated CSIRT trust).
//
// Dual-mode auth: tokens with alg=RS256 are verified via the sinauth SDK
// (OIDC/JWKS). All other tokens use the existing HS256 path so existing
// sessions continue to work without any changes.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/opensecstack/sdk/go/sinauth"
)

type Role string

const (
	RoleViewer       Role = "viewer"
	RoleAnalyst      Role = "analyst"
	RoleOperator     Role = "operator"
	RoleAdmin        Role = "admin"
	RoleCSIRTLead    Role = "csirt_lead"
	RoleExternalPeer Role = "external_peer"
)

func (r Role) Valid() bool {
	switch r {
	case RoleViewer, RoleAnalyst, RoleOperator, RoleAdmin, RoleCSIRTLead, RoleExternalPeer:
		return true
	}
	return false
}

// rank gives a total order for "X ≥ Y" checks. Higher rank = more access.
// External peers sit between viewer and analyst — they can read public
// advisories and ingest IOCs but cannot triage internal incidents.
var rank = map[Role]int{
	RoleViewer:       1,
	RoleExternalPeer: 2,
	RoleAnalyst:      3,
	RoleOperator:     4,
	RoleCSIRTLead:    5,
	RoleAdmin:        6,
}

func (r Role) AtLeast(other Role) bool {
	return rank[r] >= rank[other]
}

// Rank returns the numeric rank of a role. Higher values have more access.
// Returns 0 for unknown roles.
func Rank(r Role) int {
	return rank[r]
}

type Claims struct {
	Sub  string `json:"sub"`
	Role Role   `json:"role"`
	jwt.RegisteredClaims
}

type Authenticator struct {
	secrets    [][]byte // accept multiple for rotation; sign with [0]
	issuer     string
	ttl        time.Duration
	pepper     string
	users      map[string]userRecord // username → record
	sinauthURL string                // issuer URL for RS256 sinauth tokens

	// sinauth client is initialised lazily so startup does not hard-depend
	// on sinauth being reachable.
	sinauthOnce   sync.Once
	sinauthClient *sinauth.Client
	sinauthErr    error
}

type userRecord struct {
	UserID uuid.UUID
	Role   Role
	Hash   []byte
}

func New(secrets [][]byte, issuer string, ttl time.Duration, pepper, users string) (*Authenticator, error) {
	return NewWithSinauth(secrets, issuer, ttl, pepper, users, "")
}

// NewWithSinauth is like New but also configures a sinauth issuer URL for
// RS256 dual-mode verification. sinauthURL may be empty to disable RS256.
func NewWithSinauth(secrets [][]byte, issuer string, ttl time.Duration, pepper, users, sinauthURL string) (*Authenticator, error) {
	if len(secrets) == 0 {
		return nil, errors.New("auth: at least one JWT secret required")
	}
	a := &Authenticator{
		secrets:    secrets,
		issuer:     issuer,
		ttl:        ttl,
		pepper:     pepper,
		users:      make(map[string]userRecord),
		sinauthURL: sinauthURL,
	}
	if users != "" {
		if err := a.loadUsers(users); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// loadUsers parses comma-separated `username:role:sha256hex` triples.
// The hash is sha256(pepper + password) — same convention as OpenScrub.
func (a *Authenticator) loadUsers(spec string) error {
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) != 3 {
			return errors.New("auth: user entry must be username:role:sha256hex")
		}
		role := Role(parts[1])
		if !role.Valid() {
			return errors.New("auth: invalid role " + parts[1])
		}
		raw, err := hex.DecodeString(parts[2])
		if err != nil || len(raw) != 32 {
			return errors.New("auth: invalid sha256 hex for user " + parts[0])
		}
		a.users[parts[0]] = userRecord{
			UserID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("opencsirt:user:"+parts[0])),
			Role:   role,
			Hash:   raw,
		}
	}
	return nil
}

// Login validates credentials and mints a token. Returns ErrIssuerDisabled
// when no users are loaded (deploy-time issuer disabled).
var (
	ErrIssuerDisabled = errors.New("auth: issuer disabled (no users configured)")
	ErrInvalidCreds   = errors.New("auth: invalid credentials")
)

func (a *Authenticator) Login(username, password string) (string, *Claims, error) {
	if len(a.users) == 0 {
		return "", nil, ErrIssuerDisabled
	}
	rec, ok := a.users[username]
	if !ok {
		return "", nil, ErrInvalidCreds
	}
	want := sha256.Sum256([]byte(a.pepper + ":" + password))
	if subtle.ConstantTimeCompare(want[:], rec.Hash) != 1 {
		return "", nil, ErrInvalidCreds
	}
	now := time.Now().UTC()
	claims := &Claims{
		Sub:  rec.UserID.String(),
		Role: rec.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(a.ttl)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(a.secrets[0])
	return signed, claims, err
}

// Verify parses + validates a token against any rotation secret.
// Only a signature-mismatch error (wrong key tried) causes the loop to
// continue; any other error (expired, malformed, wrong algorithm) is
// authoritative and is returned immediately — trying another key cannot fix it.
func (a *Authenticator) Verify(tokenStr string) (*Claims, error) {
	for _, secret := range a.secrets {
		c := &Claims{}
		_, err := jwt.ParseWithClaims(tokenStr, c, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return secret, nil
		})
		if err == nil && c.Role.Valid() {
			return c, nil
		}
		// Signature invalid just means this key is wrong — try the next one.
		// Any other error (expired, malformed, alg mismatch) is definitive.
		if err != nil && !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, err
		}
	}
	return nil, errors.New("auth: token verification failed")
}

// jwtHeaderAlg parses only the JWT header segment (no signature check) and
// returns the "alg" field. Returns "" on any parse error.
func jwtHeaderAlg(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return ""
	}
	return hdr.Alg
}

// HTTP middleware.

type ctxKey int

const claimsKey ctxKey = 0

// Middleware validates the Bearer JWT. RS256 tokens are routed to the sinauth
// SDK; all other algorithms use the existing HS256 path so existing sessions
// continue to work without changes.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(h, "Bearer ")

		// Dual-mode: RS256 → sinauth, everything else → HS256.
		if jwtHeaderAlg(tokenStr) == "RS256" {
			sinauthURL := a.sinauthURL
			if sinauthURL == "" {
				sinauthURL = "http://localhost:8100"
			}
			a.sinauthOnce.Do(func() {
				a.sinauthClient, a.sinauthErr = sinauth.New(sinauthURL)
			})
			if a.sinauthErr != nil {
				http.Error(w, "sinauth unavailable", http.StatusUnauthorized)
				return
			}
			sc, err := a.sinauthClient.VerifyToken(r.Context(), tokenStr)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			// Map sinauth role string to the Role type; default to viewer if unknown.
			role := Role(sc.Role)
			if !role.Valid() {
				role = RoleViewer
			}
			c := &Claims{
				Sub:  sc.Sub,
				Role: role,
			}
			ctx := context.WithValue(r.Context(), claimsKey, c)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// HS256 path (existing logic unchanged).
		c, err := a.Verify(tokenStr)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, c)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ClaimsFrom(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*Claims)
	return c, ok
}

// ContextWithClaims returns a copy of ctx carrying c, exactly as Middleware
// would set it after successfully verifying a bearer token. Exported so
// handler-level tests can simulate an authenticated request (real Sub/Role)
// without needing a signed JWT or a live sinauth instance.
func ContextWithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

func RequireRole(min Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := ClaimsFrom(r.Context())
			if !ok {
				http.Error(w, "no claims", http.StatusUnauthorized)
				return
			}
			if !c.Role.AtLeast(min) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
