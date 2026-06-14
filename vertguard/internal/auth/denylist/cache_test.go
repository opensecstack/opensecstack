package denylist

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/opensecstack/vertguard/internal/auth"
)

// failingStore lets tests inject backend errors.
type failingStore struct {
	inner *MemoryStore
	err   error
}

func (f *failingStore) List(ctx context.Context) ([]Entry, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.inner.List(ctx)
}
func (f *failingStore) Add(ctx context.Context, e Entry) error    { return f.inner.Add(ctx, e) }
func (f *failingStore) Remove(ctx context.Context, k, v string) error {
	return f.inner.Remove(ctx, k, v)
}

func TestCache_IsRevoked_JTIHit(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Add(context.Background(), Entry{Kind: KindJTI, Value: "abc", Reason: "compromised"})
	c := NewCache(s)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	revoked, reason := c.IsRevoked(&auth.Claims{Sub: "u1", Jti: "abc"})
	if !revoked || reason != "compromised" {
		t.Fatalf("want revoked+reason, got revoked=%v reason=%q", revoked, reason)
	}
}

func TestCache_IsRevoked_SubHit(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Add(context.Background(), Entry{Kind: KindSub, Value: "alice", Reason: "off-boarded"})
	c := NewCache(s)
	_ = c.Refresh(context.Background())
	revoked, reason := c.IsRevoked(&auth.Claims{Sub: "alice", Jti: "x"})
	if !revoked || reason != "off-boarded" {
		t.Fatalf("want revoked, got revoked=%v reason=%q", revoked, reason)
	}
}

func TestCache_IsRevoked_Miss(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Add(context.Background(), Entry{Kind: KindJTI, Value: "abc"})
	c := NewCache(s)
	_ = c.Refresh(context.Background())
	if revoked, _ := c.IsRevoked(&auth.Claims{Sub: "bob", Jti: "zzz"}); revoked {
		t.Fatal("unexpected revoke")
	}
}

func TestCache_IsRevoked_ExpiredEntryIgnored(t *testing.T) {
	s := NewMemoryStore()
	past := time.Now().Add(-time.Minute)
	_ = s.Add(context.Background(), Entry{Kind: KindJTI, Value: "abc", ExpiresAt: &past})
	c := NewCache(s)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if revoked, _ := c.IsRevoked(&auth.Claims{Jti: "abc"}); revoked {
		t.Fatal("expired entry should not block")
	}
	if c.Size() != 0 {
		t.Fatalf("expected empty snapshot, got %d", c.Size())
	}
}

func TestCache_NilSafe(t *testing.T) {
	var c *Cache
	if revoked, _ := c.IsRevoked(&auth.Claims{Jti: "x"}); revoked {
		t.Fatal("nil cache should not report revoked")
	}
	if c.Size() != 0 {
		t.Fatal("nil cache size should be 0")
	}
}

func TestCache_RefreshPickUpStoreChanges(t *testing.T) {
	s := NewMemoryStore()
	c := NewCache(s)
	_ = c.Refresh(context.Background())
	if revoked, _ := c.IsRevoked(&auth.Claims{Jti: "later"}); revoked {
		t.Fatal("should be empty initially")
	}
	// Underlying store changes; refresh should pick it up.
	_ = s.Add(context.Background(), Entry{Kind: KindJTI, Value: "later", Reason: "rotated"})
	if revoked, _ := c.IsRevoked(&auth.Claims{Jti: "later"}); revoked {
		t.Fatal("snapshot should not yet contain new entry")
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	revoked, reason := c.IsRevoked(&auth.Claims{Jti: "later"})
	if !revoked || reason != "rotated" {
		t.Fatalf("after refresh: revoked=%v reason=%q", revoked, reason)
	}
}

func TestCache_RefreshErrorKeepsLastSnapshot(t *testing.T) {
	inner := NewMemoryStore()
	_ = inner.Add(context.Background(), Entry{Kind: KindJTI, Value: "abc"})
	fs := &failingStore{inner: inner}
	c := NewCache(fs)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if c.Size() != 1 {
		t.Fatalf("size=%d want 1", c.Size())
	}
	fs.err = errors.New("db down")
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("expected error from failing store")
	}
	// Snapshot should not be wiped.
	if c.Size() != 1 {
		t.Fatalf("snapshot wiped on error: size=%d", c.Size())
	}
}

func TestCache_MetricsHook(t *testing.T) {
	m := &fakeMetrics{}
	s := NewMemoryStore()
	_ = s.Add(context.Background(), Entry{Kind: KindJTI, Value: "abc"})
	c := NewCache(s, WithMetrics(m))
	_ = c.Refresh(context.Background())
	if m.size != 1 {
		t.Fatalf("size hook=%d want 1", m.size)
	}
	c.IsRevoked(&auth.Claims{Jti: "abc"})
	if m.hits[KindJTI] != 1 {
		t.Fatalf("jti hit=%d want 1", m.hits[KindJTI])
	}
}

type fakeMetrics struct {
	size int
	hits map[string]int
}

func (f *fakeMetrics) SetDenylistSize(n int) { f.size = n }
func (f *fakeMetrics) IncDenylistHit(kind string) {
	if f.hits == nil {
		f.hits = map[string]int{}
	}
	f.hits[kind]++
}
