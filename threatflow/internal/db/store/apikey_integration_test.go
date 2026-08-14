//go:build integration

package store

import (
	"context"
	"testing"
	"time"
)

func TestIntegration_APIKey_CreateAndFindByHash(t *testing.T) {
	pool := testDB(t)
	s := NewAPIKeyStore(pool)
	ctx := context.Background()

	key := &APIKey{
		Name:    "ci-runner",
		KeyHash: HashAPIKey("plaintext-secret"),
		Role:    "admin",
		Enabled: true,
	}
	mustOK(t, s.Create(ctx, key), "create")
	if key.ID.String() == "" {
		t.Fatal("expected ID to be populated")
	}

	got, err := s.FindByHash(ctx, HashAPIKey("plaintext-secret"))
	mustOK(t, err, "find by hash")
	if got.Name != "ci-runner" || got.Role != "admin" {
		t.Errorf("unexpected key: %+v", got)
	}

	if _, err := s.FindByHash(ctx, HashAPIKey("wrong-secret")); err != ErrNotFound {
		t.Errorf("want ErrNotFound for unknown hash, got %v", err)
	}
}

func TestIntegration_APIKey_FindByHash_SkipsDisabledAndExpired(t *testing.T) {
	pool := testDB(t)
	s := NewAPIKeyStore(pool)
	ctx := context.Background()

	disabled := &APIKey{Name: "disabled", KeyHash: HashAPIKey("d1"), Role: "viewer", Enabled: false}
	mustOK(t, s.Create(ctx, disabled), "create disabled")
	if _, err := s.FindByHash(ctx, HashAPIKey("d1")); err != ErrNotFound {
		t.Errorf("disabled key should not be found, got %v", err)
	}

	past := time.Now().UTC().Add(-time.Hour)
	expired := &APIKey{Name: "expired", KeyHash: HashAPIKey("e1"), Role: "viewer", Enabled: true, ExpiresAt: &past}
	mustOK(t, s.Create(ctx, expired), "create expired")
	if _, err := s.FindByHash(ctx, HashAPIKey("e1")); err != ErrNotFound {
		t.Errorf("expired key should not be found, got %v", err)
	}

	future := time.Now().UTC().Add(time.Hour)
	valid := &APIKey{Name: "valid", KeyHash: HashAPIKey("v1"), Role: "viewer", Enabled: true, ExpiresAt: &future}
	mustOK(t, s.Create(ctx, valid), "create valid")
	got, err := s.FindByHash(ctx, HashAPIKey("v1"))
	mustOK(t, err, "find valid")
	if got.Name != "valid" {
		t.Errorf("name = %q, want valid", got.Name)
	}
}

func TestIntegration_APIKey_List(t *testing.T) {
	pool := testDB(t)
	s := NewAPIKeyStore(pool)
	ctx := context.Background()

	mustOK(t, s.Create(ctx, &APIKey{Name: "k1", KeyHash: HashAPIKey("k1"), Role: "viewer", Enabled: true}), "create k1")
	mustOK(t, s.Create(ctx, &APIKey{Name: "k2", KeyHash: HashAPIKey("k2"), Role: "admin", Enabled: true}), "create k2")

	list, err := s.List(ctx)
	mustOK(t, err, "list")
	if len(list) != 2 {
		t.Fatalf("len(list) = %d, want 2", len(list))
	}
}

func TestIntegration_APIKey_TouchUsed(t *testing.T) {
	pool := testDB(t)
	s := NewAPIKeyStore(pool)
	ctx := context.Background()

	key := &APIKey{Name: "touch-me", KeyHash: HashAPIKey("touch"), Role: "viewer", Enabled: true}
	mustOK(t, s.Create(ctx, key), "create")

	s.TouchUsed(ctx, key.ID)

	got, err := s.FindByHash(ctx, HashAPIKey("touch"))
	mustOK(t, err, "find after touch")
	if got.LastUsedAt == nil {
		t.Error("expected LastUsedAt to be set after TouchUsed")
	}

	// TouchUsed against an unknown ID is best-effort and must not panic.
	s.TouchUsed(ctx, key.ID)
}

func TestIntegration_APIKey_RevokeAndDelete(t *testing.T) {
	pool := testDB(t)
	s := NewAPIKeyStore(pool)
	ctx := context.Background()

	key := &APIKey{Name: "revoke-me", KeyHash: HashAPIKey("revoke"), Role: "viewer", Enabled: true}
	mustOK(t, s.Create(ctx, key), "create")

	mustOK(t, s.Revoke(ctx, key.ID), "revoke")
	if _, err := s.FindByHash(ctx, HashAPIKey("revoke")); err != ErrNotFound {
		t.Errorf("revoked key should not be found via FindByHash, got %v", err)
	}

	mustOK(t, s.Delete(ctx, key.ID), "delete")

	if err := s.Delete(ctx, key.ID); err != ErrNotFound {
		t.Errorf("delete of missing key: want ErrNotFound, got %v", err)
	}
	if err := s.Revoke(ctx, key.ID); err != ErrNotFound {
		t.Errorf("revoke of missing key: want ErrNotFound, got %v", err)
	}
}
