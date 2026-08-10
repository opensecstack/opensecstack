package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestMemoryOverrideStore_Add_RejectsInvalidKind(t *testing.T) {
	s := NewMemoryOverrideStore()
	err := s.Add(context.Background(), Override{Kind: "bogus", Value: "x", RPS: 1, Burst: 1})
	if err == nil {
		t.Fatal("expected an error for an invalid Kind")
	}
}

func TestMemoryOverrideStore_Add_RejectsEmptyValue(t *testing.T) {
	s := NewMemoryOverrideStore()
	err := s.Add(context.Background(), Override{Kind: KindSub, Value: "", RPS: 1, Burst: 1})
	if err == nil {
		t.Fatal("expected an error for an empty Value")
	}
}

func TestMemoryOverrideStore_Add_AutoFillsCreatedAt(t *testing.T) {
	s := NewMemoryOverrideStore()
	ctx := context.Background()
	if err := s.Add(ctx, Override{Kind: KindIP, Value: "1.2.3.4", RPS: 1, Burst: 1}); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].CreatedAt.IsZero() {
		t.Error("CreatedAt was not auto-filled")
	}
}

// TestMemoryOverrideStore_Add_ReplacesExistingEntry verifies that
// adding an override for the same (kind, value) pair replaces the
// prior entry rather than accumulating duplicates.
func TestMemoryOverrideStore_Add_ReplacesExistingEntry(t *testing.T) {
	s := NewMemoryOverrideStore()
	ctx := context.Background()
	if err := s.Add(ctx, Override{Kind: KindSub, Value: "dup", RPS: 1, Burst: 1}); err != nil {
		t.Fatalf("add 1: %v", err)
	}
	if err := s.Add(ctx, Override{Kind: KindSub, Value: "dup", RPS: 50, Burst: 50}); err != nil {
		t.Fatalf("add 2: %v", err)
	}
	got, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1 (replace, not accumulate)", len(got))
	}
	if got[0].RPS != 50 {
		t.Errorf("RPS = %v, want 50 (latest write should win)", got[0].RPS)
	}
}

func TestMemoryOverrideStore_Remove_DeletesEntry(t *testing.T) {
	s := NewMemoryOverrideStore()
	ctx := context.Background()
	if err := s.Add(ctx, Override{Kind: KindSub, Value: "gone", RPS: 1, Burst: 1}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.Remove(ctx, KindSub, "gone"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	got, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0 after Remove", len(got))
	}
}

func TestMemoryOverrideStore_Remove_UnknownEntry_NoError(t *testing.T) {
	s := NewMemoryOverrideStore()
	if err := s.Remove(context.Background(), KindSub, "never-existed"); err != nil {
		t.Fatalf("Remove of an unknown entry should be a no-op, got error: %v", err)
	}
}

// TestMemoryOverrideStore_List_SortedNewestFirst verifies the ordering
// contract documented on List — callers (e.g. the admin UI) depend on
// newest-first ordering to show recent overrides at the top.
func TestMemoryOverrideStore_List_SortedNewestFirst(t *testing.T) {
	s := NewMemoryOverrideStore()
	ctx := context.Background()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	entries := []struct {
		value string
		at    time.Time
	}{
		{"oldest", base},
		{"middle", base.Add(1 * time.Hour)},
		{"newest", base.Add(2 * time.Hour)},
	}
	for _, e := range entries {
		if err := s.Add(ctx, Override{Kind: KindSub, Value: e.value, RPS: 1, Burst: 1, CreatedAt: e.at}); err != nil {
			t.Fatalf("add %s: %v", e.value, err)
		}
	}

	got, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len(got) = %d, want 3", len(got))
	}
	wantOrder := []string{"newest", "middle", "oldest"}
	for i, w := range wantOrder {
		if got[i].Value != w {
			t.Errorf("position %d: Value = %q, want %q (order = %v)", i, got[i].Value, w, got)
		}
	}
}
