package token

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Verifier validates RS256 access tokens.
type Verifier struct {
	publicKey *rsa.PublicKey
	issuer    string
}

// NewVerifier creates a new Verifier.
func NewVerifier(publicKey *rsa.PublicKey, issuer string) *Verifier {
	return &Verifier{
		publicKey: publicKey,
		issuer:    issuer,
	}
}

// Verify parses and validates an access token, returning its claims.
func (v *Verifier) Verify(tokenStr string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}

	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("token: unexpected signing method: %v", t.Header["alg"])
		}
		return v.publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))

	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("token: invalid token")
	}

	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("token: issuer mismatch: got %q, want %q", claims.Issuer, v.issuer)
	}

	return claims, nil
}
