package auth

import (
	"testing"
	"time"
)

func TestSession_Active(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	t.Run("not expired, not revoked -> active", func(t *testing.T) {
		s := &Session{ExpiresAt: future}
		if !s.Active(now) {
			t.Fatalf("want active")
		}
	})
	t.Run("expired -> inactive", func(t *testing.T) {
		s := &Session{ExpiresAt: past}
		if s.Active(now) {
			t.Fatalf("want inactive (expired)")
		}
	})
	t.Run("revoked -> inactive even if not expired", func(t *testing.T) {
		revokedAt := now.Add(-time.Minute)
		s := &Session{ExpiresAt: future, RevokedAt: &revokedAt}
		if s.Active(now) {
			t.Fatalf("want inactive (revoked)")
		}
	})
}

func TestHashRefreshToken_Deterministic(t *testing.T) {
	h1 := HashRefreshToken("token-a")
	h2 := HashRefreshToken("token-a")
	if h1 != h2 {
		t.Fatalf("HashRefreshToken not deterministic: %q vs %q", h1, h2)
	}
	h3 := HashRefreshToken("token-b")
	if h1 == h3 {
		t.Fatalf("HashRefreshToken collided for different inputs")
	}
	if len(h1) != 64 { // hex-encoded SHA-256
		t.Fatalf("HashRefreshToken length: got %d, want 64", len(h1))
	}
}

func TestMemorySessionStore_CreateRejectsEmptyID(t *testing.T) {
	store := NewMemorySessionStore()
	err := store.Create(Session{ID: "", RefreshTokenHash: "h"})
	if err == nil {
		t.Fatalf("Create: want error for empty session ID")
	}
}

func TestMemorySessionStore_CreateRejectsEmptyHash(t *testing.T) {
	store := NewMemorySessionStore()
	err := store.Create(Session{ID: "s1", RefreshTokenHash: ""})
	if err == nil {
		t.Fatalf("Create: want error for empty refresh token hash")
	}
}

func TestMemorySessionStore_CreateAndGetByRefreshToken(t *testing.T) {
	store := NewMemorySessionStore()
	refreshTok := "raw-refresh-token"
	sess := Session{
		ID:               "s1",
		UserID:           "u1",
		RefreshTokenHash: HashRefreshToken(refreshTok),
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	if err := store.Create(sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := store.GetByRefreshToken(refreshTok)
	if err != nil {
		t.Fatalf("GetByRefreshToken: %v", err)
	}
	if got.ID != "s1" || got.UserID != "u1" {
		t.Fatalf("GetByRefreshToken: got %+v", got)
	}
}

func TestMemorySessionStore_GetByRefreshToken_NotFound(t *testing.T) {
	store := NewMemorySessionStore()
	_, err := store.GetByRefreshToken("nonexistent")
	if err != ErrSessionNotFound {
		t.Fatalf("GetByRefreshToken: got err=%v, want ErrSessionNotFound", err)
	}
}

func TestMemorySessionStore_Validate(t *testing.T) {
	store := NewMemorySessionStore()
	refreshTok := "tok"

	t.Run("active session validates", func(t *testing.T) {
		err := store.Create(Session{
			ID:               "s-active",
			RefreshTokenHash: HashRefreshToken(refreshTok),
			ExpiresAt:        time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := store.Validate(refreshTok)
		if err != nil || got.ID != "s-active" {
			t.Fatalf("Validate: got=%v err=%v", got, err)
		}
	})

	t.Run("expired session fails validation", func(t *testing.T) {
		expiredTok := "expired-tok"
		err := store.Create(Session{
			ID:               "s-expired",
			RefreshTokenHash: HashRefreshToken(expiredTok),
			ExpiresAt:        time.Now().Add(-time.Hour),
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := store.Validate(expiredTok); err != ErrSessionNotFound {
			t.Fatalf("Validate: got err=%v, want ErrSessionNotFound for expired session", err)
		}
	})
}

func TestMemorySessionStore_Revoke(t *testing.T) {
	store := NewMemorySessionStore()
	refreshTok := "tok-revoke"
	if err := store.Create(Session{
		ID:               "s1",
		RefreshTokenHash: HashRefreshToken(refreshTok),
		ExpiresAt:        time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.Revoke("s1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := store.Validate(refreshTok); err != ErrSessionNotFound {
		t.Fatalf("Validate after revoke: got err=%v, want ErrSessionNotFound", err)
	}

	// Idempotent: revoking an unknown session ID is not an error.
	if err := store.Revoke("does-not-exist"); err != nil {
		t.Fatalf("Revoke unknown session: got error %v, want nil (idempotent)", err)
	}
}

func TestMemorySessionStore_RevokeAll(t *testing.T) {
	store := NewMemorySessionStore()
	for i, id := range []string{"s1", "s2"} {
		tok := "tok-" + id
		if err := store.Create(Session{
			ID:               id,
			UserID:           "u1",
			RefreshTokenHash: HashRefreshToken(tok),
			ExpiresAt:        time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}
	// Session belonging to a different user must not be touched.
	if err := store.Create(Session{
		ID:               "s3",
		UserID:           "u2",
		RefreshTokenHash: HashRefreshToken("tok-s3"),
		ExpiresAt:        time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Create s3: %v", err)
	}

	if err := store.RevokeAll("u1"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	if _, err := store.Validate("tok-s1"); err != ErrSessionNotFound {
		t.Fatalf("s1 should be revoked, got err=%v", err)
	}
	if _, err := store.Validate("tok-s2"); err != ErrSessionNotFound {
		t.Fatalf("s2 should be revoked, got err=%v", err)
	}
	if _, err := store.Validate("tok-s3"); err != nil {
		t.Fatalf("s3 (different user) should remain active, got err=%v", err)
	}

	// RevokeAll on a user with no sessions is a no-op, not an error.
	if err := store.RevokeAll("no-such-user"); err != nil {
		t.Fatalf("RevokeAll unknown user: got error %v, want nil", err)
	}
}

func TestNewSessionID_ReturnsNonEmptyUnique(t *testing.T) {
	id1 := NewSessionID()
	id2 := NewSessionID()
	if id1 == "" || id2 == "" {
		t.Fatalf("NewSessionID: got empty id")
	}
	if id1 == id2 {
		t.Fatalf("NewSessionID: two calls returned identical IDs %q", id1)
	}
}
