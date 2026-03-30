package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rlOKHandler is a trivial handler that always responds 200 OK, used by rate
// limiter tests. Named with "rl" prefix to avoid collision with the okHandler
// declared in auth_test.go (same package).
var rlOKHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// doRequest fires one GET request through the given handler from the given
// remoteAddr (host:port) and optional X-Forwarded-For header value.
func doRequest(t *testing.T, h http.Handler, remoteAddr, xff string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestRateLimiter_UnderLimit verifies that requests up to the configured rate
// all receive a 200 response.
func TestRateLimiter_UnderLimit(t *testing.T) {
	const rate = 5
	rl := NewRateLimiter(rate)
	defer rl.Stop()

	h := rl.Middleware(rlOKHandler)
	for i := 0; i < rate; i++ {
		rr := doRequest(t, h, "10.0.0.1:1234", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rr.Code)
		}
	}
}

// TestRateLimiter_AtLimit verifies that the request exactly at the limit (the
// n-th request when rate == n) is still allowed (200), not blocked.
func TestRateLimiter_AtLimit(t *testing.T) {
	// rate = 3 means 3 requests per window are allowed.
	// The first request resets the counter to 1 (allowed).
	// The second increments to 2 (allowed, 2 <= 3).
	// The third increments to 3 (allowed, 3 <= 3).
	const rate = 3
	rl := NewRateLimiter(rate)
	defer rl.Stop()

	h := rl.Middleware(rlOKHandler)
	for i := 0; i < rate; i++ {
		rr := doRequest(t, h, "10.0.0.2:9000", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d/%d: got %d, want 200", i+1, rate, rr.Code)
		}
	}
}

// TestRateLimiter_OverLimit verifies that the (n+1)-th request is blocked with
// 429 and includes the expected headers / body fields.
func TestRateLimiter_OverLimit(t *testing.T) {
	const rate = 3
	rl := NewRateLimiter(rate)
	defer rl.Stop()

	h := rl.Middleware(rlOKHandler)
	// Exhaust the allowance.
	for i := 0; i < rate; i++ {
		doRequest(t, h, "10.0.0.3:5555", "")
	}

	// This request exceeds the limit.
	rr := doRequest(t, h, "10.0.0.3:5555", "")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want 429", rr.Code)
	}

	if rr.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header absent on 429 response")
	}

	// Decode body and check for RATE_LIMITED code.
	var body map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if got, ok := body["code"]; !ok || got != "RATE_LIMITED" {
		t.Errorf("body[\"code\"] = %v, want \"RATE_LIMITED\"", got)
	}
	if _, ok := body["retry_after"]; !ok {
		t.Error("body missing \"retry_after\" field")
	}
	if _, ok := body["error"]; !ok {
		t.Error("body missing \"error\" field")
	}
}

// TestRateLimiter_IndependentCounters verifies that two different client IPs
// have fully independent rate-limit counters.
func TestRateLimiter_IndependentCounters(t *testing.T) {
	const rate = 2
	rl := NewRateLimiter(rate)
	defer rl.Stop()

	h := rl.Middleware(rlOKHandler)

	// Exhaust IP A.
	for i := 0; i < rate; i++ {
		doRequest(t, h, "192.168.1.1:1000", "")
	}
	// IP A should now be blocked.
	rrA := doRequest(t, h, "192.168.1.1:1000", "")
	if rrA.Code != http.StatusTooManyRequests {
		t.Errorf("IP A: got %d, want 429 after exhausting limit", rrA.Code)
	}

	// IP B has its own counter — first request must succeed.
	rrB := doRequest(t, h, "192.168.1.2:2000", "")
	if rrB.Code != http.StatusOK {
		t.Errorf("IP B: got %d, want 200 (independent counter)", rrB.Code)
	}
}

// TestRateLimiter_CounterIncrements verifies the basic counter mechanics:
// the first request for a new IP starts at 1 (allowed), and each subsequent
// request within the same window increments the counter.
// This test does not (and cannot reasonably) test the actual 1-minute reset
// without mocking time; it documents the expected behaviour structure.
func TestRateLimiter_CounterIncrements(t *testing.T) {
	const rate = 10
	rl := NewRateLimiter(rate)
	defer rl.Stop()

	h := rl.Middleware(rlOKHandler)
	const ip = "172.16.0.1:8080"

	// All requests within the rate should succeed.
	for i := 0; i < rate; i++ {
		rr := doRequest(t, h, ip, "")
		if rr.Code != http.StatusOK {
			t.Errorf("request %d: got %d, want 200", i+1, rr.Code)
		}
	}
	// The next one should be blocked.
	rr := doRequest(t, h, ip, "")
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("request %d: got %d, want 429", rate+1, rr.Code)
	}
}

// TestParseTrustedProxyCIDRs exercises the CIDR-parsing helper.
func TestParseTrustedProxyCIDRs(t *testing.T) {
	t.Run("valid CIDR", func(t *testing.T) {
		nets := ParseTrustedProxyCIDRs([]string{"192.168.0.0/24"})
		if len(nets) != 1 {
			t.Fatalf("got %d nets, want 1", len(nets))
		}
		if nets[0].String() != "192.168.0.0/24" {
			t.Errorf("net = %s, want 192.168.0.0/24", nets[0])
		}
	})

	t.Run("plain IP treated as /32", func(t *testing.T) {
		nets := ParseTrustedProxyCIDRs([]string{"10.0.0.1"})
		if len(nets) != 1 {
			t.Fatalf("got %d nets, want 1", len(nets))
		}
		// net.ParseCIDR normalises 10.0.0.1/32 → 10.0.0.1/32.
		if nets[0].String() != "10.0.0.1/32" {
			t.Errorf("net = %s, want 10.0.0.1/32", nets[0])
		}
	})

	t.Run("invalid entry skipped", func(t *testing.T) {
		nets := ParseTrustedProxyCIDRs([]string{"not-an-ip", "10.0.0.0/8"})
		if len(nets) != 1 {
			t.Fatalf("got %d nets, want 1 (invalid entry should be skipped)", len(nets))
		}
		if nets[0].String() != "10.0.0.0/8" {
			t.Errorf("net = %s, want 10.0.0.0/8", nets[0])
		}
	})

	t.Run("empty input", func(t *testing.T) {
		nets := ParseTrustedProxyCIDRs([]string{})
		if len(nets) != 0 {
			t.Errorf("got %d nets, want 0", len(nets))
		}
	})

	t.Run("nil input", func(t *testing.T) {
		nets := ParseTrustedProxyCIDRs(nil)
		if len(nets) != 0 {
			t.Errorf("got %d nets, want 0", len(nets))
		}
	})

	t.Run("multiple valid CIDRs", func(t *testing.T) {
		nets := ParseTrustedProxyCIDRs([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
		if len(nets) != 3 {
			t.Fatalf("got %d nets, want 3", len(nets))
		}
	})
}

// TestRateLimiter_Stop verifies Stop() is idempotent and does not panic when
// called multiple times.
func TestRateLimiter_Stop(t *testing.T) {
	rl := NewRateLimiter(10)
	// Calling Stop multiple times must not panic.
	rl.Stop()
	rl.Stop()
	rl.Stop()
}

// TestRateLimiter_TrustedProxyXFFUsed verifies that when the direct peer IP is
// in the trusted proxy CIDR the X-Forwarded-For header is used as the client IP.
func TestRateLimiter_TrustedProxyXFFUsed(t *testing.T) {
	const rate = 2
	// Trust the proxy at 10.10.10.1.
	rl := NewRateLimiterWithProxies(rate, []string{"10.10.10.1/32"})
	defer rl.Stop()

	h := rl.Middleware(rlOKHandler)

	// Exhaust the allowance for the XFF client 1.2.3.4 coming through the proxy.
	for i := 0; i < rate; i++ {
		rr := doRequest(t, h, "10.10.10.1:9999", "1.2.3.4")
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rr.Code)
		}
	}

	// Now 1.2.3.4 is blocked.
	rr := doRequest(t, h, "10.10.10.1:9999", "1.2.3.4")
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("XFF client 1.2.3.4 should be rate-limited; got %d", rr.Code)
	}

	// A different XFF client (5.6.7.8) through the same proxy is unaffected.
	rr = doRequest(t, h, "10.10.10.1:9999", "5.6.7.8")
	if rr.Code != http.StatusOK {
		t.Errorf("XFF client 5.6.7.8 should not be limited yet; got %d", rr.Code)
	}
}

// TestRateLimiter_TrustedProxyXFFIgnored verifies that when the direct peer IP
// is NOT in the trusted proxy CIDR the XFF header is ignored and RemoteAddr is
// used as the client identity instead.
func TestRateLimiter_TrustedProxyXFFIgnored(t *testing.T) {
	const rate = 2
	// Only trust 10.10.10.1; the request below comes from an untrusted peer.
	rl := NewRateLimiterWithProxies(rate, []string{"10.10.10.1/32"})
	defer rl.Stop()

	h := rl.Middleware(rlOKHandler)

	// Exhaust the allowance for the untrusted peer's RemoteAddr (192.0.2.99).
	for i := 0; i < rate; i++ {
		rr := doRequest(t, h, "192.0.2.99:4321", "1.2.3.4")
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rr.Code)
		}
	}

	// The untrusted peer (192.0.2.99) should now be limited — XFF was ignored.
	rr := doRequest(t, h, "192.0.2.99:4321", "1.2.3.4")
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("untrusted peer should be rate-limited by RemoteAddr; got %d", rr.Code)
	}

	// The XFF IP (1.2.3.4) itself was never tracked, so it must still be free.
	// Simulate 1.2.3.4 directly connecting (not through a proxy).
	rr = doRequest(t, h, "1.2.3.4:8080", "")
	if rr.Code != http.StatusOK {
		t.Errorf("1.2.3.4 direct (not via proxy) should not be limited; got %d", rr.Code)
	}
}

// TestRateLimiter_NoTrustedProxies verifies that when no trusted proxies are
// configured the XFF header is always ignored.
func TestRateLimiter_NoTrustedProxies(t *testing.T) {
	const rate = 2
	rl := NewRateLimiter(rate) // no trusted proxies
	defer rl.Stop()

	h := rl.Middleware(rlOKHandler)

	// Exhaust allowance for RemoteAddr 10.0.0.1.
	for i := 0; i < rate; i++ {
		rr := doRequest(t, h, "10.0.0.1:1111", "9.9.9.9")
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rr.Code)
		}
	}

	// 10.0.0.1 is now limited; the XFF IP 9.9.9.9 was never used as the key.
	rr := doRequest(t, h, "10.0.0.1:1111", "9.9.9.9")
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("10.0.0.1 should be limited; got %d", rr.Code)
	}
}

// TestRateLimiter_XFFMultipleValues verifies that when XFF contains multiple
// comma-separated values only the first (leftmost, i.e. original client) is used.
func TestRateLimiter_XFFMultipleValues(t *testing.T) {
	const rate = 2
	rl := NewRateLimiterWithProxies(rate, []string{"10.10.10.1/32"})
	defer rl.Stop()

	h := rl.Middleware(rlOKHandler)

	// Exhaust allowance for 1.1.1.1 (leftmost XFF entry).
	for i := 0; i < rate; i++ {
		rr := doRequest(t, h, "10.10.10.1:9999", "1.1.1.1, 2.2.2.2, 3.3.3.3")
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, rr.Code)
		}
	}

	rr := doRequest(t, h, "10.10.10.1:9999", "1.1.1.1, 2.2.2.2, 3.3.3.3")
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("1.1.1.1 (leftmost XFF) should be rate-limited; got %d", rr.Code)
	}
}
