package db

import (
	"context"
	"testing"
	"time"

	"github.com/opensecstack/vertguard/internal/auth/denylist"
)

func TestDenylist_SaveListRemoveIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "token_denylist")
	ctx := context.Background()

	e := &denylist.Entry{
		Kind:      "jti",
		Value:     "token-abc",
		Reason:    "compromised",
		RevokedBy: "admin",
	}
	if err := d.SaveDenylistEntry(ctx, e); err != nil {
		t.Fatalf("SaveDenylistEntry: %v", err)
	}

	list, err := d.ListDenylistEntries(ctx)
	if err != nil {
		t.Fatalf("ListDenylistEntries: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list))
	}
	if list[0].Value != "token-abc" || list[0].Kind != "jti" {
		t.Errorf("unexpected entry: %+v", list[0])
	}
	if list[0].Reason != "compromised" {
		t.Errorf("Reason: got %q, want compromised", list[0].Reason)
	}

	if err := d.RemoveDenylistEntry(ctx, "jti", "token-abc"); err != nil {
		t.Fatalf("RemoveDenylistEntry: %v", err)
	}
	list, err = d.ListDenylistEntries(ctx)
	if err != nil {
		t.Fatalf("ListDenylistEntries after remove: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 entries after remove, got %d", len(list))
	}
}

func TestDenylist_RemoveNonexistentIsIdempotentIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "token_denylist")

	if err := d.RemoveDenylistEntry(context.Background(), "jti", "does-not-exist"); err != nil {
		t.Errorf("RemoveDenylistEntry on missing row should not error, got: %v", err)
	}
}

func TestDenylist_SaveUpsertsOnConflictIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "token_denylist")
	ctx := context.Background()

	e := &denylist.Entry{Kind: "sub", Value: "user-1", Reason: "first"}
	if err := d.SaveDenylistEntry(ctx, e); err != nil {
		t.Fatalf("SaveDenylistEntry (first): %v", err)
	}

	e2 := &denylist.Entry{Kind: "sub", Value: "user-1", Reason: "updated"}
	if err := d.SaveDenylistEntry(ctx, e2); err != nil {
		t.Fatalf("SaveDenylistEntry (conflict): %v", err)
	}

	list, err := d.ListDenylistEntries(ctx)
	if err != nil {
		t.Fatalf("ListDenylistEntries: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected upsert to keep exactly 1 row, got %d", len(list))
	}
	if list[0].Reason != "updated" {
		t.Errorf("Reason after upsert: got %q, want updated", list[0].Reason)
	}
}

func TestDenylist_ListExcludesExpiredIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "token_denylist")
	ctx := context.Background()

	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)

	expired := &denylist.Entry{Kind: "jti", Value: "expired-token", ExpiresAt: &past}
	active := &denylist.Entry{Kind: "jti", Value: "active-token", ExpiresAt: &future}
	if err := d.SaveDenylistEntry(ctx, expired); err != nil {
		t.Fatalf("SaveDenylistEntry (expired): %v", err)
	}
	if err := d.SaveDenylistEntry(ctx, active); err != nil {
		t.Fatalf("SaveDenylistEntry (active): %v", err)
	}

	list, err := d.ListDenylistEntries(ctx)
	if err != nil {
		t.Fatalf("ListDenylistEntries: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected only the active entry, got %d entries", len(list))
	}
	if list[0].Value != "active-token" {
		t.Errorf("expected active-token, got %q", list[0].Value)
	}
}

func TestDenylistStore_AddListRemoveIntegration(t *testing.T) {
	d := openTestDB(t)
	truncateTables(t, d, "token_denylist")
	ctx := context.Background()
	store := NewDenylistStore(d)

	if err := store.Add(ctx, denylist.Entry{Kind: "jti", Value: "wrapper-token"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(list))
	}
	if err := store.Remove(ctx, "jti", "wrapper-token"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	list, err = store.List(ctx)
	if err != nil {
		t.Fatalf("List after remove: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 entries after remove, got %d", len(list))
	}
}
