package token

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Issuer signs access tokens and ID tokens with RS256.
type Issuer struct {
	privateKey *rsa.PrivateKey
	keyID      string
	issuer     string
}

// NewIssuer creates a new Issuer.
func NewIssuer(privateKey *rsa.PrivateKey, keyID, issuer string) *Issuer {
	return &Issuer{
		privateKey: privateKey,
		keyID:      keyID,
		issuer:     issuer,
	}
}

// AccessTokenClaims are the claims in a sinauth access token.
type AccessTokenClaims struct {
	Sub      string   `json:"sub"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scope"`
	jwt.RegisteredClaims
}

// IDTokenClaims are the claims in a sinauth ID token (OIDC).
type IDTokenClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	Azp           string `json:"azp,omitempty"` // authorized party (client_id)
	jwt.RegisteredClaims
}

// IssueAccessToken creates a signed RS256 access token.
func (i *Issuer) IssueAccessToken(sub, clientID string, scopes []string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := AccessTokenClaims{
		Sub:      sub,
		ClientID: clientID,
		Scopes:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Issuer:    i.issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.keyID

	return tok.SignedString(i.privateKey)
}

// IssueAccessTokenWithRoles creates a signed RS256 access token that includes
// per-client role assignments in the "client_roles" claim. If clientRoles is
// non-empty, the first entry is also set as the primary "role" claim.
func (i *Issuer) IssueAccessTokenWithRoles(sub, clientID string, scopes, clientRoles []string, ttl time.Duration) (string, error) {
	now := time.Now()

	type accessTokenWithRolesClaims struct {
		Sub         string   `json:"sub"`
		ClientID    string   `json:"client_id"`
		Scopes      []string `json:"scope"`
		Role        string   `json:"role,omitempty"`
		ClientRoles []string `json:"client_roles,omitempty"`
		jwt.RegisteredClaims
	}

	var primaryRole string
	if len(clientRoles) > 0 {
		primaryRole = clientRoles[0]
	}

	claims := accessTokenWithRolesClaims{
		Sub:         sub,
		ClientID:    clientID,
		Scopes:      scopes,
		Role:        primaryRole,
		ClientRoles: clientRoles,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Issuer:    i.issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.keyID

	return tok.SignedString(i.privateKey)
}

// IssueIDToken creates a signed RS256 ID token.
func (i *Issuer) IssueIDToken(sub, clientID, nonce, email, name, picture string, emailVerified bool, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := IDTokenClaims{
		Sub:           sub,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		Picture:       picture,
		Nonce:         nonce,
		Azp:           clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Issuer:    i.issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = i.keyID

	return tok.SignedString(i.privateKey)
}
