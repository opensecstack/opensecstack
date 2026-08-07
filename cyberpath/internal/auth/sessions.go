package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Session is a server-side refresh-token record. The refresh token
// itself is never stored — only its SHA-256 hash, so a DB dump cannot
// be replayed against the API.
type Session struct {
	ID               string
	UserID           string
	RefreshTokenHash string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	IPAddress        string
	UserAgent        string
}

// Active reports whether the session is neither expired nor revoked.
func (s *Session) Active(now time.Time) bool {
	if s.RevokedAt != nil {
		return false
	}
	return now.Before(s.ExpiresAt)
}

// SessionStore persists refresh-token sessions. The v0.0.1 default is
// the in-memory MemorySessionStore. A Postgres-backed store will land
// alongside the `sessions` table in v1.0.0 (see TODO below).
//
// Decision (v0.0.1): in-memory.
//
//   - Pros: zero schema churn during the auth bring-up; simpler tests;
//     correct behaviour on a single-replica deploy.
//   - Cons: sessions evaporate on restart (users must log in again);
//     refresh-token revocation does not propagate across replicas.
//
// For production multi-replica deploys this is unacceptable — track
// the migration in ROADMAP under v1.0.0 "auth.sessions table".
type SessionStore interface {
	Create(s Session) error
	GetByRefreshToken(refreshToken string) (*Session, error)
	Revoke(sessionID string) error
	RevokeAll(userID string) error
	// Validate is a convenience that hashes the wire token, looks up
	// the session, and returns it iff Active.
	Validate(refreshToken string) (*Session, error)
}

// HashRefreshToken returns the lookup key stored in
// Session.RefreshTokenHash. Exposed so callers can pre-compute it.
func HashRefreshToken(refreshToken string) string {
	sum := sha256.Sum256([]byte(refreshToken))
	return hex.EncodeToString(sum[:])
}

// NewSessionID returns a fresh UUID for SessionStore.Create.
func NewSessionID() string { return uuid.NewString() }

// ErrSessionNotFound is returned when no live session matches the input.
var ErrSessionNotFound = errors.New("auth: session not found")

// MemorySessionStore is an in-memory SessionStore for v0.0.1.
//
// TODO(v1.0.0): replace with internal/db/session_store.go backed by a
// `sessions` table (id, user_id, refresh_token_hash, issued_at,
// expires_at, revoked_at, ip_address, user_agent), with the same
// interface so the swap is a single wire-up edit in cmd/server/main.go.
type MemorySessionStore struct {
	mu   sync.RWMutex
	byID map[string]*Session // sessionID -> *Session
	byHs map[string]string   // refreshTokenHash -> sessionID
	now  func() time.Time
}

// NewMemorySessionStore returns an empty in-memory store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		byID: make(map[string]*Session),
		byHs: make(map[string]string),
		now:  time.Now,
	}
}

// Create persists a new session. Returns an error if ID is empty.
func (m *MemorySessionStore) Create(s Session) error {
	if s.ID == "" {
		return errors.New("auth: session id empty")
	}
	if s.RefreshTokenHash == "" {
		return errors.New("auth: refresh token hash empty")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[s.ID] = &s
	m.byHs[s.RefreshTokenHash] = s.ID
	return nil
}

// GetByRefreshToken returns the matching session (active or not).
func (m *MemorySessionStore) GetByRefreshToken(refreshToken string) (*Session, error) {
	hs := HashRefreshToken(refreshToken)
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byHs[hs]
	if !ok {
		return nil, ErrSessionNotFound
	}
	sess, ok := m.byID[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	cp := *sess
	return &cp, nil
}

// Validate returns the session iff it is active.
func (m *MemorySessionStore) Validate(refreshToken string) (*Session, error) {
	s, err := m.GetByRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}
	if !s.Active(m.now()) {
		return nil, ErrSessionNotFound
	}
	return s, nil
}

// Revoke marks the session revoked. Idempotent: revoking an unknown
// or already-revoked session returns nil.
func (m *MemorySessionStore) Revoke(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[sessionID]
	if !ok {
		return nil
	}
	if s.RevokedAt == nil {
		t := m.now()
		s.RevokedAt = &t
	}
	return nil
}

// RevokeAll revokes every session for a user. Returns nil even when
// the user has no sessions (idempotent).
func (m *MemorySessionStore) RevokeAll(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for _, s := range m.byID {
		if s.UserID == userID && s.RevokedAt == nil {
			t := now
			s.RevokedAt = &t
		}
	}
	return nil
}
