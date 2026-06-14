package denylist

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStore_AddListRemove(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	// Force deterministic timestamps for ordering check.
	t0 := time.Now()
	if err := s.Add(ctx, Entry{Kind: KindJTI, Value: "j1", RevokedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, Entry{Kind: KindSub, Value: "alice", RevokedAt: t0.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	out, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("len=%d want 2", len(out))
	}
	// newest first
	if out[0].Value != "alice" {
		t.Fatalf("unexpected order: %+v", out)
	}

	if err := s.Remove(ctx, KindJTI, "j1"); err != nil {
		t.Fatal(err)
	}
	out, _ = s.List(ctx)
	if len(out) != 1 || out[0].Value != "alice" {
		t.Fatalf("after remove unexpected: %+v", out)
	}

	// Remove of missing row is a no-op.
	if err := s.Remove(ctx, KindJTI, "ghost"); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryStore_RejectsInvalidKind(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Add(context.Background(), Entry{Kind: "bogus", Value: "x"}); err == nil {
		t.Fatal("expected error on invalid kind")
	}
	if err := s.Add(context.Background(), Entry{Kind: KindJTI, Value: ""}); err == nil {
		t.Fatal("expected error on empty value")
	}
}
