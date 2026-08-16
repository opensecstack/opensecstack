package handlers

// White-box test for the unexported resolveUserID helper. It lives in
// package handlers (not handlers_test) because resolveUserID has no
// exported surface of its own.

import (
	"context"
	"testing"
)

func TestResolveUserID_Found_ReturnsID(t *testing.T) {
	pool := NewTestDBPool(t)

	username := "resolve_" + RandomSuffix()
	var wantID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, display_name, role) VALUES ($1,$1,'author') RETURNING id`,
		username,
	).Scan(&wantID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	CleanupUserByUsername(t, pool, username)

	gotID := resolveUserID(context.Background(), pool, username)
	if gotID != wantID {
		t.Errorf("expected resolveUserID to return %q, got %q", wantID, gotID)
	}
}

func TestResolveUserID_NotFound_ReturnsEmptyString(t *testing.T) {
	pool := NewTestDBPool(t)

	got := resolveUserID(context.Background(), pool, "nonexistent_"+RandomSuffix())
	if got != "" {
		t.Errorf("expected empty string for nonexistent user, got %q", got)
	}
}
