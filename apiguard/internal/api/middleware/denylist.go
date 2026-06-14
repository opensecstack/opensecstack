package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// denylistEntry holds the expiry time of a denied access token.
type denylistEntry struct {
	expiresAt time.Time
}

// TokenDenylist is a thread-safe, TTL-bounded in-memory set of denied access
// token identifiers. Entries are automatically reaped once the token's natural
// expiry is reached, keeping memory usage bounded by the number of tokens that
// were logged out before they expired naturally.
//
// The key stored is the hex-encoded SHA-256 hash of the raw token string.
// No DB persistence is required because the TTL is always <= the token's
// remaining lifetime: after the token would have expired anyway, the entry
// is irrelevant and may be discarded.
type TokenDenylist struct {
	mu      sync.RWMutex
	entries map[string]denylistEntry
	stopCh  chan struct{}
	once    sync.Once
}

// NewTokenDenylist creates and starts a TokenDenylist. Call Stop() when the
// server shuts down to release the background reaper goroutine.
func NewTokenDenylist() *TokenDenylist {
	d := &TokenDenylist{
		entries: make(map[string]denylistEntry),
		stopCh:  make(chan struct{}),
	}
	go d.reap()
	return d
}

// Add inserts tokenHash into the denylist until expiresAt. If expiresAt is in
// the past the call is a no-op (the token is already expired and will be
// rejected by the normal expiry check).
func (d *TokenDenylist) Add(tokenHash string, expiresAt time.Time) {
	if !time.Now().Before(expiresAt) {
		return
	}
	d.mu.Lock()
	d.entries[tokenHash] = denylistEntry{expiresAt: expiresAt}
	d.mu.Unlock()
}

// IsDenied reports whether the given tokenHash is present and not yet expired.
func (d *TokenDenylist) IsDenied(tokenHash string) bool {
	d.mu.RLock()
	entry, ok := d.entries[tokenHash]
	d.mu.RUnlock()
	return ok && time.Now().Before(entry.expiresAt)
}

// Stop halts the background reaper goroutine. Safe to call more than once.
func (d *TokenDenylist) Stop() {
	d.once.Do(func() { close(d.stopCh) })
}

// reap removes expired entries every minute to prevent unbounded growth.
func (d *TokenDenylist) reap() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case now := <-ticker.C:
			d.mu.Lock()
			for k, e := range d.entries {
				if !now.Before(e.expiresAt) {
					delete(d.entries, k)
				}
			}
			d.mu.Unlock()
		}
	}
}

// HashToken returns the hex-encoded SHA-256 hash of rawToken. Used to derive
// the denylist key from the raw bearer token string.
func HashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}
