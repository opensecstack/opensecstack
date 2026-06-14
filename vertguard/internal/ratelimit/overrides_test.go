package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestSetOverrides_AllowUsesOverrideRPS(t *testing.T) {
	// Default = generous; override = block-on-first.
	l := New(Config{RPS: 100, Burst: 100})
	defer l.Stop()
	l.SetOverrides([]Override{{Kind: KindSub, Value: "abuser", RPS: 0, Burst: 0}})

	if l.Allow("sub:abuser") {
		t.Fatal("override RPS=0 burst=0 should block immediately")
	}
	// A non-overridden key still uses the default config.
	if !l.Allow("sub:other") {
		t.Fatal("non-overridden key should pass with default 100 burst")
	}
}

func TestSetOverrides_RemovedOverrideFallsBackToDefault(t *testing.T) {
	// Default tight, override loose. Removing the override after the
	// bucket has been built keeps the override rate (documented LIMITATION
	// — see SetOverrides godoc).
	l := New(Config{RPS: 1, Burst: 1, IdleTTL: 10 * time.Millisecond, CleanupInterval: 5 * time.Millisecond})
	defer l.Stop()

	l.SetOverrides([]Override{{Kind: KindSub, Value: "vip", RPS: 100, Burst: 100}})
	for i := 0; i < 5; i++ {
		if !l.Allow("sub:vip") {
			t.Fatalf("override-loose key should still allow at i=%d", i)
		}
	}

	// Drop the override and wait for the janitor to evict the bucket so
	// the next Allow constructs a fresh default-rate bucket.
	// 200ms >> IdleTTL(10ms) + CleanupInterval(5ms) — reliable under system load.
	l.SetOverrides(nil)
	time.Sleep(200 * time.Millisecond)

	// Default RPS=1 / burst=1 — first call passes, immediate second is
	// limited.
	if !l.Allow("sub:vip") {
		t.Fatal("post-eviction first request should pass with default burst")
	}
	if l.Allow("sub:vip") {
		t.Fatal("post-eviction second request should hit the default limit")
	}
}

func TestSetOverrides_TwoKeysIndependentBuckets(t *testing.T) {
	l := New(Config{RPS: 100, Burst: 100})
	defer l.Stop()
	l.SetOverrides([]Override{{Kind: KindSub, Value: "blocked", RPS: 0, Burst: 0}})

	if l.Allow("sub:blocked") {
		t.Fatal("blocked key should be denied")
	}
	if !l.Allow("sub:open") {
		t.Fatal("open key must not be affected by another key's override")
	}
}

func TestMemoryOverrideStore_FiltersExpired(t *testing.T) {
	s := NewMemoryOverrideStore()
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	if err := s.Add(ctx, Override{Kind: KindSub, Value: "stale", RPS: 1, Burst: 1, ExpiresAt: &past}); err != nil {
		t.Fatalf("add stale: %v", err)
	}
	if err := s.Add(ctx, Override{Kind: KindSub, Value: "fresh", RPS: 1, Burst: 1}); err != nil {
		t.Fatalf("add fresh: %v", err)
	}

	got, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Value != "fresh" {
		t.Fatalf("expected only 'fresh', got %+v", got)
	}
}

type stubOverrideHook struct {
	hits   map[string]int
	active int
}

func (s *stubOverrideHook) IncOverrideHit(kind, decision string) {
	if s.hits == nil {
		s.hits = map[string]int{}
	}
	s.hits[kind+":"+decision]++
}
func (s *stubOverrideHook) SetActiveOverrides(n int) { s.active = n }

func TestSetOverrides_HookFiresOnOverrideKey(t *testing.T) {
	l := New(Config{RPS: 100, Burst: 100})
	defer l.Stop()

	hook := &stubOverrideHook{}
	l.SetOverrideHook(hook)
	l.SetOverrides([]Override{{Kind: KindSub, Value: "x", RPS: 0, Burst: 1}})

	if !l.Allow("sub:x") {
		t.Fatal("burst=1 should allow first request")
	}
	if l.Allow("sub:x") {
		t.Fatal("RPS=0 should deny the second request")
	}
	// Non-override key must NOT increment the hook counter.
	l.Allow("sub:other")

	if hook.active != 1 {
		t.Fatalf("active = %d, want 1", hook.active)
	}
	if hook.hits["sub:allowed"] != 1 || hook.hits["sub:limited"] != 1 {
		t.Fatalf("hits = %+v, want one allowed + one limited", hook.hits)
	}
}
