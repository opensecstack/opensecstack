package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP_StripsPortIPv4(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:54321"
	if got := clientIP(req); got != "203.0.113.5" {
		t.Errorf("clientIP() = %q, want %q", got, "203.0.113.5")
	}
}

func TestClientIP_StripsPortIPv6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:54321"
	if got := clientIP(req); got != "[::1]" {
		t.Errorf("clientIP() = %q, want %q", got, "[::1]")
	}
}

func TestClientIP_NoPortReturnsAsIs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5"
	if got := clientIP(req); got != "203.0.113.5" {
		t.Errorf("clientIP() = %q, want %q", got, "203.0.113.5")
	}
}

func TestIndexPort_IPv4(t *testing.T) {
	if got := indexPort("1.2.3.4:80"); got != 7 {
		t.Errorf("indexPort() = %d, want 7", got)
	}
}

func TestIndexPort_Empty(t *testing.T) {
	if got := indexPort(""); got != -1 {
		t.Errorf("indexPort(\"\") = %d, want -1", got)
	}
}

func TestIndexPort_NoColonReturnsNegOne(t *testing.T) {
	if got := indexPort("hostwithnoport"); got != -1 {
		t.Errorf("indexPort() = %d, want -1", got)
	}
}

func TestIndexPort_MultipleColonsWithoutBracketsReturnsNegOne(t *testing.T) {
	// A bare (unbracketed) IPv6 address has more than one colon and no
	// brackets — indexPort must not misidentify one of them as a port
	// separator (that would silently truncate the address).
	if got := indexPort("::1"); got != -1 {
		t.Errorf("indexPort(\"::1\") = %d, want -1 (ambiguous, no brackets)", got)
	}
}

func TestIndexPort_BracketedIPv6(t *testing.T) {
	addr := "[2001:db8::1]:8080"
	idx := indexPort(addr)
	if idx < 0 || addr[idx] != ':' || addr[:idx] != "[2001:db8::1]" {
		t.Errorf("indexPort(%q) = %d", addr, idx)
	}
}

func TestNewRateLimiter_AllowsBurstThenBlocks(t *testing.T) {
	rl := NewRateLimiter(1, 2) // 1 req/sec, burst of 2
	ip := "198.51.100.9"

	if !rl.allow(ip) {
		t.Fatal("first request within burst should be allowed")
	}
	if !rl.allow(ip) {
		t.Fatal("second request within burst should be allowed")
	}
	if rl.allow(ip) {
		t.Fatal("third immediate request should exceed burst and be denied")
	}
}

func TestNewRateLimiter_DifferentIPsHaveIndependentBuckets(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	if !rl.allow("10.0.0.1") {
		t.Fatal("first IP should be allowed its first request")
	}
	if !rl.allow("10.0.0.2") {
		t.Fatal("a different IP must have its own independent bucket")
	}
}

func TestMiddleware_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(100, 10)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := rl.Middleware()(next)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.1:1111"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestMiddleware_Returns429WhenExceeded(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := rl.Middleware()(next)

	ip := "192.0.2.2:2222"

	// Exhaust the single-token burst.
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = ip
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = ip
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second immediate request status = %d, want 429", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429 response")
	}
}

