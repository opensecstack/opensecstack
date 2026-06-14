package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Credential is one (username, role, password-hash) tuple. Password
// hashes use SHA-256(pepper || ":" || password) — chosen for v1.0.0
// because we have no bcrypt dep and the credential set is tiny
// (one to five operator accounts seeded from env, never user-supplied).
// External IDP integration is the v1.1.0 plan; this issuer is the
// minimal in-house path so the dashboard works without one.
type Credential struct {
	Username string
	Role     string
	Hash     string // hex-encoded sha256
}

// CredentialStore is the lookup used by Issuer.
type CredentialStore struct {
	pepper string
	users  map[string]Credential
}

// NewCredentialStore parses the OPENSCRUB_USERS env-var format:
//
//	"alice:admin:<sha256hex>,bob:operator:<sha256hex>"
//
// Lines that don't match are skipped with no error so a partially
// configured deployment still boots; missing creds simply make the
// login endpoint return 401 for that user.
func NewCredentialStore(pepper, spec string) *CredentialStore {
	s := &CredentialStore{pepper: pepper, users: map[string]Credential{}}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 3)
		if len(parts) != 3 {
			continue
		}
		s.users[parts[0]] = Credential{
			Username: parts[0],
			Role:     parts[1],
			Hash:     strings.ToLower(parts[2]),
		}
	}
	return s
}

// Empty reports whether no credentials were seeded — Server uses this
// to disable the /auth/login endpoint cleanly (returning 503 instead
// of an opaque 401) when no user is configured.
func (s *CredentialStore) Empty() bool { return len(s.users) == 0 }

// Verify returns the matched Credential when (username, password) is
// valid. The comparison is constant-time on the hash.
func (s *CredentialStore) Verify(username, password string) (Credential, error) {
	c, ok := s.users[username]
	if !ok {
		// Still hash to keep the timing roughly constant.
		_ = HashPassword(s.pepper, password)
		return Credential{}, errors.New("invalid credentials")
	}
	want, err := hex.DecodeString(c.Hash)
	if err != nil {
		return Credential{}, errors.New("invalid credentials")
	}
	got, err := hex.DecodeString(HashPassword(s.pepper, password))
	if err != nil {
		return Credential{}, errors.New("invalid credentials")
	}
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return Credential{}, errors.New("invalid credentials")
	}
	return c, nil
}

// HashPassword is exported so an operator helper (cmd/openscrub-mkhash
// or `make user`) can produce the hex digest to drop into OPENSCRUB_USERS.
func HashPassword(pepper, password string) string {
	sum := sha256.Sum256([]byte(pepper + ":" + password))
	return hex.EncodeToString(sum[:])
}

// Issuer mints HS256 tokens. The same secret is used by HS256Verifier
// (primary slot only — rotation slots are read by the verifier and
// never written by the issuer).
type Issuer struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

// NewIssuer builds an Issuer. ttl<=0 → 1h.
func NewIssuer(secret, issuer string, ttl time.Duration) *Issuer {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Issuer{secret: []byte(secret), issuer: issuer, ttl: ttl}
}

// Mint signs and returns a token + its expiry. Returns an error if the
// secret is empty (refusing to mint an unverifiable token).
func (i *Issuer) Mint(sub, role string) (string, time.Time, error) {
	if len(i.secret) == 0 {
		return "", time.Time{}, errors.New("issuer: no secret configured")
	}
	exp := time.Now().Add(i.ttl)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  sub,
		"role": role,
		"iss":  i.issuer,
		"iat":  time.Now().Unix(),
		"exp":  exp.Unix(),
	})
	signed, err := tok.SignedString(i.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign token: %w", err)
	}
	return signed, exp, nil
}
