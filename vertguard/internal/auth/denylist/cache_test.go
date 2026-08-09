package denylist

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"

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

func TestWithRefreshInterval(t *testing.T) {
	s := NewMemoryStore()
	c := NewCache(s, WithRefreshInterval(5*time.Second))
	if c.interval != 5*time.Second {
		t.Fatalf("interval = %v, want 5s", c.interval)
	}
	// Zero/negative values must be ignored, keeping the default.
	c2 := NewCache(s, WithRefreshInterval(0))
	if c2.interval != DefaultRefreshInterval {
		t.Fatalf("interval with 0 override = %v, want default %v", c2.interval, DefaultRefreshInterval)
	}
	c3 := NewCache(s, WithRefreshInterval(-time.Second))
	if c3.interval != DefaultRefreshInterval {
		t.Fatalf("interval with negative override = %v, want default %v", c3.interval, DefaultRefreshInterval)
	}
}

func TestWithLogger(t *testing.T) {
	l := zerolog.Nop()
	s := NewMemoryStore()
	c := NewCache(s, WithLogger(&l))
	if c.logger != &l {
		t.Fatalf("logger not set as expected")
	}
}

func TestWithClock(t *testing.T) {
	fixed := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewMemoryStore()
	c := NewCache(s, withClock(func() time.Time { return fixed }))
	if got := c.now(); !got.Equal(fixed) {
		t.Fatalf("now() = %v, want %v", got, fixed)
	}
	// Passing nil must not override the existing clock.
	c2 := NewCache(s, withClock(nil))
	if c2.now == nil {
		t.Fatal("now func should not be nil after withClock(nil)")
	}
}

func TestCache_RunAndClose(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Add(context.Background(), Entry{Kind: KindJTI, Value: "abc"})
	c := NewCache(s, WithRefreshInterval(5*time.Millisecond))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	// Wait for at least one refresh tick to land the entry in the snapshot.
	deadline := time.Now().Add(2 * time.Second)
	for c.Size() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c.Size() != 1 {
		t.Fatalf("Run() did not refresh snapshot in time, size=%d", c.Size())
	}

	c.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Close")
	}

	// Close must be idempotent (no panic on double-close).
	c.Close()
}

func TestCache_RunReturnsOnCtxCancel(t *testing.T) {
	s := NewMemoryStore()
	c := NewCache(s, WithRefreshInterval(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestCache_RunSecondCallIsNoop(t *testing.T) {
	s := NewMemoryStore()
	c := NewCache(s, WithRefreshInterval(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done1 := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done1)
	}()
	// Give the first Run a moment to install the ticker, then call again;
	// per the doc comment ("Safe to invoke once per Cache") the second
	// call must return immediately rather than installing a second ticker.
	deadline := time.Now().Add(time.Second)
	for c.ticker == nil && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	done2 := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done2)
	}()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("second Run() call did not return immediately")
	}
	cancel()
	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("first Run did not return after context cancel")
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
