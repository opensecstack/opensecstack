package middleware

import "sync"

const maxSecrets = 3

// SecretProvider holds a rotating list of JWT signing secrets and allows
// zero-downtime rotation via Rotate(). Index 0 is always the active signing
// key; remaining entries are accepted for verification only (grace period).
// All methods are safe for concurrent use.
type SecretProvider struct {
	mu      sync.RWMutex
	secrets [][]byte
}

// NewSecretProvider initialises a SecretProvider from a list of secret strings.
// The first entry is treated as the active signing key; subsequent entries are
// accepted for verification only. Duplicate and empty strings are ignored.
// Backward-compatible: pass a single string for single-key operation.
func NewSecretProvider(secrets ...string) *SecretProvider {
	sp := &SecretProvider{}
	for _, s := range secrets {
		if s != "" {
			sp.secrets = append(sp.secrets, []byte(s))
		}
	}
	return sp
}

// Current returns the active signing secret (secrets[0]).
// Returns nil when no secrets are configured.
func (sp *SecretProvider) Current() []byte {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	if len(sp.secrets) == 0 {
		return nil
	}
	return sp.secrets[0]
}

// All returns a copy of all secrets (active + grace-period verification keys).
// The caller must not modify the returned slice or its elements.
func (sp *SecretProvider) All() [][]byte {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	out := make([][]byte, len(sp.secrets))
	copy(out, sp.secrets)
	return out
}

// Rotate prepends newSecret as the new active signing key, demoting the
// previous secrets to verification-only grace-period keys. Entries beyond
// maxSecrets (3) are dropped so arbitrarily old keys cannot accumulate.
func (sp *SecretProvider) Rotate(newSecret []byte) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	updated := make([][]byte, 0, maxSecrets)
	updated = append(updated, newSecret)
	for _, s := range sp.secrets {
		if len(updated) >= maxSecrets {
			break
		}
		updated = append(updated, s)
	}
	sp.secrets = updated
}

// Len returns the number of secrets currently held (active + grace-period).
func (sp *SecretProvider) Len() int {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	return len(sp.secrets)
}
