package auth

import (
	"fmt"

	"github.com/opensecstack/sdk/password"
)

// NewHasher constructs an Argon2id hasher from this package's Config.
//
// The pepper is read from cfg.Secret-adjacent configuration — in serve
// wiring we translate config.AuthConfig.Pepper into this field. Callers
// that need to hash API keys or user passwords should resolve this hasher
// once at startup and share the *password.Hasher across request handlers
// (it is safe for concurrent use).
//
// Returns (nil, error) when Pepper is empty or too short so misconfiguration
// surfaces at startup, not the first time someone tries to log in.
func NewHasher(cfg Config) (*password.Hasher, error) {
	if cfg.Pepper == "" {
		return nil, fmt.Errorf("auth.NewHasher: pepper is not configured (set IRFLOW_AUTH_PEPPER)")
	}
	h, err := password.NewHasher(cfg.Pepper)
	if err != nil {
		return nil, fmt.Errorf("auth.NewHasher: %w", err)
	}
	return h, nil
}
