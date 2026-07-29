// Package auth bridges CITADEL's identity checks to sinauth, the
// ecosystem's OIDC identity provider. See
// adrs/005-sinauth-identity-bridge.md: CITADEL previously authenticated via
// a local `sessions` table that nothing ever populated; this package
// verifies sinauth-issued bearer tokens directly instead.
package auth

import (
	"context"
	"fmt"

	sinauth "github.com/opensecstack/sdk/go/sinauth"
)

// SinauthVerifier implements marshal.TokenVerifier by verifying tokens
// against a sinauth instance's JWKS (via sdk/go/sinauth.Client — the same
// library apiguard/irflow/threatflow already use in their own auth
// middleware).
type SinauthVerifier struct {
	client *sinauth.Client
}

// NewSinauthVerifier constructs a verifier for the given sinauth issuer URL
// (e.g. "https://auth.sin.to"). Fetches the OIDC discovery document once;
// returns an error if sinauth is unreachable or misconfigured — CITADEL
// should fail fast at startup rather than run with a broken AuthN gate.
func NewSinauthVerifier(issuerURL string) (*SinauthVerifier, error) {
	client, err := sinauth.New(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: constructing sinauth client: %w", err)
	}
	return &SinauthVerifier{client: client}, nil
}

// Verify implements marshal.TokenVerifier.
func (v *SinauthVerifier) Verify(ctx context.Context, token string) (userID, role string, err error) {
	claims, err := v.client.VerifyToken(ctx, token)
	if err != nil {
		return "", "", err
	}
	return claims.Sub, claims.Role, nil
}
