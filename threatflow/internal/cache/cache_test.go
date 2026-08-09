package cache

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

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
