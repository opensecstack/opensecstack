package keys

import (
	"encoding/base64"
	"math/big"
)

// JWK represents a single JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"` // base64url-encoded modulus
	E   string `json:"e"` // base64url-encoded exponent
}

// JWKS is the JSON Web Key Set returned by /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// BuildJWKS constructs a JWKS from the manager's current public key.
func (m *Manager) BuildJWKS() JWKS {
	pub := m.PublicKey()

	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: m.KeyID(),
				Alg: "RS256",
				N:   n,
				E:   e,
			},
		},
	}
}
