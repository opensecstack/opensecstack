package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/rs/zerolog"
)

// newTestCache spins up an in-process miniredis server and returns a Cache
// wired to it via a real Open() call, so the "enabled" code paths (Get/Set/
// Invalidate actually talking to Redis) get exercised with a real client,
// not just the disabled no-op branch.
func newTestCache(t *testing.T, ttl time.Duration) *Cache {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := Open(context.Background(), "redis://"+mr.Addr(), ttl, zerolog.Nop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestOpen_EmptyURLReturnsNoOpCache proves the documented no-op contract: an
// empty Redis URL must not attempt to dial anything and must yield a cache
// that is safe to use but reports itself disabled.
func TestOpen_EmptyURLReturnsNoOpCache(t *testing.T) {
	c, err := Open(context.Background(), "", time.Minute, zerolog.Nop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if c.Enabled() {
		t.Fatal("expected disabled cache for empty URL")
	}
}

// TestOpen_InvalidURLReturnsError proves a malformed redis:// URL is rejected
// at Open time rather than deferred to the first Get/Set call.
func TestOpen_InvalidURLReturnsError(t *testing.T) {
	_, err := Open(context.Background(), "not-a-valid-url://::::", time.Minute, zerolog.Nop())
	if err == nil {
		t.Fatal("expected error for invalid redis url")
	}
}

// TestOpen_UnreachableRedisReturnsError proves Open pings the server and
// surfaces a connection failure rather than returning a cache that silently
// fails on every subsequent call.
func TestOpen_UnreachableRedisReturnsError(t *testing.T) {
	_, err := Open(context.Background(), "redis://127.0.0.1:1/0", time.Millisecond, zerolog.Nop())
	if err == nil {
		t.Fatal("expected error for unreachable redis")
	}
}

func TestEnabled_NilCacheIsFalse(t *testing.T) {
	var c *Cache
	if c.Enabled() {
		t.Fatal("nil cache must report disabled")
	}
}

func TestClose_NilCacheIsNoOp(t *testing.T) {
	var c *Cache
	if err := c.Close(); err != nil {
		t.Fatalf("nil cache Close should be a no-op, got %v", err)
	}
}

func TestClose_DisabledCacheIsNoOp(t *testing.T) {
	c, _ := Open(context.Background(), "", time.Minute, zerolog.Nop())
	if err := c.Close(); err != nil {
		t.Fatalf("disabled cache Close should be a no-op, got %v", err)
	}
}

func TestStats_NilCacheReturnsZero(t *testing.T) {
	var c *Cache
	hits, misses := c.Stats()
	if hits != 0 || misses != 0 {
		t.Fatalf("nil cache Stats() = (%d, %d), want (0, 0)", hits, misses)
	}
}

func TestStats_DisabledCacheReturnsZero(t *testing.T) {
	c, _ := Open(context.Background(), "", time.Minute, zerolog.Nop())
	hits, misses := c.Stats()
	if hits != 0 || misses != 0 {
		t.Fatalf("disabled cache Stats() = (%d, %d), want (0, 0)", hits, misses)
	}
}

// TestGet_DisabledCacheAlwaysMisses proves the "uniform ErrMiss" contract
// documented on Get: when the cache is disabled, every Get must return
// ErrMiss so callers can unconditionally fall through to the database
// without special-casing "cache is off".
func TestGet_DisabledCacheAlwaysMisses(t *testing.T) {
	c, _ := Open(context.Background(), "", time.Minute, zerolog.Nop())
	var out map[string]string
	err := c.Get(context.Background(), "some-key", &out)
	if err != ErrMiss {
		t.Fatalf("Get on disabled cache = %v, want ErrMiss", err)
	}
}

// TestSet_DisabledCacheIsNoOp proves Set on a disabled cache does not panic
// and does not error out (there's nothing to assert it stored, but it must
// not blow up callers that unconditionally call Set after every write).
func TestSet_DisabledCacheIsNoOp(t *testing.T) {
	c, _ := Open(context.Background(), "", time.Minute, zerolog.Nop())
	c.Set(context.Background(), "key", map[string]string{"a": "b"})
	// Round-trip through Get must still miss — Set on a disabled cache must
	// not have silently written anything anywhere Get could find.
	var out map[string]string
	if err := c.Get(context.Background(), "key", &out); err != ErrMiss {
		t.Fatalf("expected ErrMiss after Set on disabled cache, got %v", err)
	}
}

func TestInvalidate_DisabledCacheIsNoOp(t *testing.T) {
	c, _ := Open(context.Background(), "", time.Minute, zerolog.Nop())
	// Must not panic on nil client.
	c.Invalidate(context.Background(), "a", "b")
}

func TestInvalidate_NoKeysIsNoOp(t *testing.T) {
	c, _ := Open(context.Background(), "", time.Minute, zerolog.Nop())
	c.Invalidate(context.Background())
}

// TestOpen_ReachableRedisEnablesCache proves Open successfully wires an
// enabled cache against a live Redis server (rather than only ever
// exercising the empty-URL / unreachable-URL error branches).
func TestOpen_ReachableRedisEnablesCache(t *testing.T) {
	c := newTestCache(t, time.Minute)
	if !c.Enabled() {
		t.Fatal("expected cache to be enabled against a reachable redis")
	}
}

// TestSetThenGet_RoundTripsValue proves the enabled Set/Get path actually
// stores and retrieves data through Redis, not just "doesn't panic".
func TestSetThenGet_RoundTripsValue(t *testing.T) {
	c := newTestCache(t, time.Minute)
	ctx := context.Background()

	type payload struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	in := payload{Type: "ipv4-addr", Value: "198.51.100.42"}
	c.Set(ctx, "ioc:1", in)

	var out payload
	if err := c.Get(ctx, "ioc:1", &out); err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if out != in {
		t.Fatalf("Get returned %+v, want %+v", out, in)
	}

	hits, misses := c.Stats()
	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
	if misses != 0 {
		t.Errorf("misses = %d, want 0", misses)
	}
}

// TestGet_MissingKeyReturnsErrMissAndCountsMiss proves a genuine cache miss
// (key never set) surfaces ErrMiss and increments the miss counter, matching
// the "callers fall through to the DB" contract.
func TestGet_MissingKeyReturnsErrMissAndCountsMiss(t *testing.T) {
	c := newTestCache(t, time.Minute)
	var out map[string]string
	err := c.Get(context.Background(), "does-not-exist", &out)
	if err != ErrMiss {
		t.Fatalf("Get = %v, want ErrMiss", err)
	}
	_, misses := c.Stats()
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
	}
}

// TestGet_CorruptedValueReturnsErrMiss proves a value stored at the key that
// isn't valid JSON for the target type is treated as a miss (logged, not
// propagated as a decode error to the caller) — the cache must never make a
// handler fail because of a bad cache entry.
func TestGet_CorruptedValueReturnsErrMiss(t *testing.T) {
	c := newTestCache(t, time.Minute)
	ctx := context.Background()
	// Store a JSON array where the caller expects an object.
	c.Set(ctx, "bad", []int{1, 2, 3})

	var out map[string]string
	err := c.Get(ctx, "bad", &out)
	if err != ErrMiss {
		t.Fatalf("Get on type-mismatched value = %v, want ErrMiss", err)
	}
}

// TestInvalidate_RemovesKey proves Invalidate actually deletes the key from
// Redis rather than being a pure no-op on an enabled cache.
func TestInvalidate_RemovesKey(t *testing.T) {
	c := newTestCache(t, time.Minute)
	ctx := context.Background()
	c.Set(ctx, "victim", map[string]string{"a": "b"})

	var out map[string]string
	if err := c.Get(ctx, "victim", &out); err != nil {
		t.Fatalf("precondition: expected hit before invalidate, got %v", err)
	}

	c.Invalidate(ctx, "victim")

	err := c.Get(ctx, "victim", &out)
	if err != ErrMiss {
		t.Fatalf("Get after Invalidate = %v, want ErrMiss", err)
	}
}

// TestInvalidate_MultipleKeysRemovesAll proves the variadic keys... form
// deletes every listed key, not just the first.
func TestInvalidate_MultipleKeysRemovesAll(t *testing.T) {
	c := newTestCache(t, time.Minute)
	ctx := context.Background()
	c.Set(ctx, "k1", "v1")
	c.Set(ctx, "k2", "v2")

	c.Invalidate(ctx, "k1", "k2")

	var out string
	if err := c.Get(ctx, "k1", &out); err != ErrMiss {
		t.Errorf("k1 Get after Invalidate = %v, want ErrMiss", err)
	}
	if err := c.Get(ctx, "k2", &out); err != ErrMiss {
		t.Errorf("k2 Get after Invalidate = %v, want ErrMiss", err)
	}
}

// TestSet_RespectsTTL proves Set actually applies the configured TTL to the
// stored key (not e.g. leaving it persistent, which would defeat cache
// invalidation-by-expiry).
func TestSet_RespectsTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	c, err := Open(context.Background(), "redis://"+mr.Addr(), 30*time.Second, zerolog.Nop())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	c.Set(context.Background(), "ttl-key", "value")

	if got := mr.TTL("ttl-key"); got != 30*time.Second {
		t.Fatalf("stored TTL = %v, want 30s", got)
	}
}

func TestIOCMatchKey_FormatsTypeAndValue(t *testing.T) {
	got := IOCMatchKey("ip", "1.2.3.4")
	want := "tf:match:ip:1.2.3.4"
	if got != want {
		t.Errorf("IOCMatchKey() = %q, want %q", got, want)
	}
}

func TestIOCMatchKey_DistinctForDifferentValues(t *testing.T) {
	a := IOCMatchKey("ip", "1.2.3.4")
	b := IOCMatchKey("ip", "5.6.7.8")
	if a == b {
		t.Error("expected distinct keys for distinct values")
	}
}
