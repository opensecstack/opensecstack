package db

import (
	"context"
	"testing"
	"time"

	"github.com/opensecstack/vertguard/internal/ratelimit"
)

func TestRateLimitOverrideStore_AddListRemoveIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "rate_limit_overrides")
	ctx := context.Background()
	store := NewRateLimitOverrideStore(d)

	o := ratelimit.Override{
		Kind:      "sub",
		Value:     "user-42",
		RPS:       5.0,
		Burst:     10,
		Reason:    "abuse suspected",
		CreatedBy: "operator-1",
	}
	if err := store.Add(ctx, o); err != nil {
		t.Fatalf("Add: %v", err)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 override, got %d", len(list))
	}
	if list[0].Value != "user-42" || list[0].RPS != 5.0 || list[0].Burst != 10 {
		t.Errorf("unexpected override: %+v", list[0])
	}

	if err := store.Remove(ctx, "sub", "user-42"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	list, err = store.List(ctx)
	if err != nil {
		t.Fatalf("List after remove: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 overrides after remove, got %d", len(list))
	}
}

func TestRateLimitOverrideStore_AddUpsertsOnConflictIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "rate_limit_overrides")
	ctx := context.Background()
	store := NewRateLimitOverrideStore(d)

	first := ratelimit.Override{Kind: "ip", Value: "203.0.113.5", RPS: 1, Burst: 2}
	if err := store.Add(ctx, first); err != nil {
		t.Fatalf("Add (first): %v", err)
	}
	second := ratelimit.Override{Kind: "ip", Value: "203.0.113.5", RPS: 50, Burst: 100}
	if err := store.Add(ctx, second); err != nil {
		t.Fatalf("Add (conflict): %v", err)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected upsert to keep exactly 1 row, got %d", len(list))
	}
	if list[0].RPS != 50 || list[0].Burst != 100 {
		t.Errorf("expected upsert to overwrite RPS/Burst, got %+v", list[0])
	}
}

func TestRateLimitOverrideStore_ListExcludesExpiredIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "rate_limit_overrides")
	ctx := context.Background()
	store := NewRateLimitOverrideStore(d)

	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)

	expired := ratelimit.Override{Kind: "ip", Value: "expired-ip", RPS: 1, Burst: 1, ExpiresAt: &past}
	active := ratelimit.Override{Kind: "ip", Value: "active-ip", RPS: 1, Burst: 1, ExpiresAt: &future}
	if err := store.Add(ctx, expired); err != nil {
		t.Fatalf("Add (expired): %v", err)
	}
	if err := store.Add(ctx, active); err != nil {
		t.Fatalf("Add (active): %v", err)
	}

	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected only the active override, got %d", len(list))
	}
	if list[0].Value != "active-ip" {
		t.Errorf("expected active-ip, got %q", list[0].Value)
	}
}

func TestRateLimitOverrideStore_RemoveNonexistentIsIdempotentIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "rate_limit_overrides")
	store := NewRateLimitOverrideStore(d)

	if err := store.Remove(context.Background(), "sub", "does-not-exist"); err != nil {
		t.Errorf("Remove on missing row should not error, got: %v", err)
	}
}

func TestRateLimitOverrideStore_NilStoreIsSafeIntegration(t *testing.T) {
	var store *RateLimitOverrideStore

	if list, err := store.List(context.Background()); err != nil || list != nil {
		t.Errorf("List on nil store: got (%v, %v), want (nil, nil)", list, err)
	}
	if err := store.Add(context.Background(), ratelimit.Override{}); err == nil {
		t.Error("Add on nil store should error")
	}
	if err := store.Remove(context.Background(), "sub", "x"); err == nil {
		t.Error("Remove on nil store should error")
	}
}

func TestNewRateLimitOverrideStore_NilDBIntegration(t *testing.T) {
	if s := NewRateLimitOverrideStore(nil); s != nil {
		t.Errorf("NewRateLimitOverrideStore(nil) = %v, want nil", s)
	}
}
